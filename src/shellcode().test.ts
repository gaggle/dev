import { assert, assertEquals } from "jsr:@std/assert";
import { Path } from "libpkgx";
import shellcode, { datadir } from "./shellcode().ts";

// Exercises `_pkgx_chpwd_hook` end-to-end via a zsh subprocess with a fake
// `dev` binary on PATH. Reproduces the bug from issue #51 where cd-ing
// directly into a subdir of an activated devenv fails to activate and emits
// `permission denied`.

async function run_hook_in_subdir(): Promise<
  { stdout: string; stderr: string; recorded_args: string[] }
> {
  const tmp = Path.mktemp();
  const proj = tmp.join("proj").mkdir();
  const sub = proj.join("sub").mkdir();

  // Override XDG_DATA_HOME so datadir() lives in the temp tree.
  const xdg = tmp.join("xdg").mkdir();

  // Pre-create the activation marker for `proj`.
  const marker_dir = xdg.join(
    "pkgx",
    "dev",
    proj.string.slice(1),
  ).mkdir("p");
  marker_dir.join("dev.pkgx.activated").touch();

  // Fake `dev` that records its argv and emits a sentinel shell command we
  // can detect in stdout. Crucially: the real `dev` (with no args) would
  // sniff $PWD, find nothing, and exit 1 — the bug we're testing.
  const fake_bin = tmp.join("bin").mkdir();
  const fake_dev = fake_bin.join("dev");
  const log = tmp.join("dev-args.log");
  Deno.writeTextFileSync(
    fake_dev.string,
    `#!/bin/sh\nprintf '%s\\n' "$@" >> "${log.string}"\necho "echo HOOK_OK"\n`,
  );
  Deno.chmodSync(fake_dev.string, 0o755);

  const env = {
    ...Deno.env.toObject(),
    XDG_DATA_HOME: xdg.string,
    PATH: `${fake_bin.string}:${Deno.env.get("PATH") ?? ""}`,
  };

  // Generate shellcode using a PATH that resolves `dev` to our fake and an
  // XDG_DATA_HOME that points at our temp datadir (both are baked in at
  // codegen time).
  const original_path = Deno.env.get("PATH");
  const original_xdg = Deno.env.get("XDG_DATA_HOME");
  Deno.env.set("PATH", env.PATH);
  Deno.env.set("XDG_DATA_HOME", xdg.string);
  let code: string;
  try {
    code = shellcode();
  } finally {
    if (original_path !== undefined) Deno.env.set("PATH", original_path);
    if (original_xdg === undefined) Deno.env.delete("XDG_DATA_HOME");
    else Deno.env.set("XDG_DATA_HOME", original_xdg);
  }

  // Simulate the user: shell starts in HOME, then cd's directly into the
  // subdirectory of the already-activated project.
  const script = `
${code}
cd "${sub.string}"
`;

  const script_path = tmp.join("script.zsh");
  Deno.writeTextFileSync(script_path.string, script);

  const proc = await new Deno.Command("zsh", {
    args: [script_path.string],
    env,
    stdout: "piped",
    stderr: "piped",
  }).output();

  const recorded_args = log.isFile()
    ? Deno.readTextFileSync(log.string).split("\n").filter((x) => x.length > 0)
    : [];

  return {
    stdout: new TextDecoder().decode(proc.stdout),
    stderr: new TextDecoder().decode(proc.stderr),
    recorded_args,
  };
}

Deno.test("chpwd hook activates when cd-ing directly into subdir of devenv", async () => {
  const { stdout, stderr, recorded_args } = await run_hook_in_subdir();

  // The hook must invoke our fake dev and run its emitted shellcode.
  assert(
    stdout.includes("HOOK_OK"),
    `expected hook to eval dev's stdout (HOOK_OK), got stdout=${
      JSON.stringify(stdout)
    } stderr=${JSON.stringify(stderr)}`,
  );

  // Crucially: no "permission denied" from the shell trying to execute a
  // directory path as a command (the bug from issue #51).
  assert(
    !/permission denied/i.test(stderr),
    `unexpected 'permission denied' in stderr: ${stderr}`,
  );

  // dev must have been invoked with the activated dir so it sniffs the
  // right place — not invoked bare while $PWD points at the subdir.
  assertEquals(
    recorded_args.length,
    1,
    `expected dev to be called with exactly one argument, got: ${
      JSON.stringify(recorded_args)
    }`,
  );
  assert(
    recorded_args[0].endsWith("/proj"),
    `expected dev to be called with the activated dir, got: ${
      recorded_args[0]
    }`,
  );
});

Deno.test("datadir respects XDG_DATA_HOME", () => {
  const original = Deno.env.get("XDG_DATA_HOME");
  try {
    Deno.env.set("XDG_DATA_HOME", "/tmp/xdg-test");
    assertEquals(datadir().string, "/tmp/xdg-test/pkgx/dev");
  } finally {
    if (original === undefined) Deno.env.delete("XDG_DATA_HOME");
    else Deno.env.set("XDG_DATA_HOME", original);
  }
});
