import { assert, assertEquals } from "jsr:@std/assert";
import { Path } from "libpkgx";
import shellcode, { datadir } from "./shellcode().ts";

// Issue #51: cd-ing directly into a subdir of an already-activated devenv
// must activate the devenv (and not emit `permission denied`). This drives
// the generated shellcode through a real bash subprocess with a fake `dev`
// on PATH so we can assert how the chpwd hook invokes it.
Deno.test("chpwd hook activates when cd-ing into subdir of devenv (#51)", async () => {
  const tmp = Path.mktemp();
  const proj = tmp.join("proj").mkdir();
  const sub = proj.join("sub").mkdir();
  const xdg = tmp.join("xdg").mkdir();
  const bin = tmp.join("bin").mkdir();
  const log = tmp.join("dev-args.log");

  // pre-activate `proj` (not `sub`) — that's the case from the bug report
  xdg.join("pkgx", "dev").join(proj.string.slice(1)).mkdir("p")
    .join("dev.pkgx.activated").touch();

  // fake `dev` records its argv and emits a sentinel for eval to run
  const fake_dev = bin.join("dev");
  Deno.writeTextFileSync(
    fake_dev.string,
    `#!/bin/sh\nprintf '%s\\n' "$@" >> "${log}"\necho 'echo HOOK_OK'\n`,
  );
  Deno.chmodSync(fake_dev.string, 0o755);

  const env = {
    ...Deno.env.toObject(),
    PATH: `${bin}:${Deno.env.get("PATH") ?? ""}`,
    XDG_DATA_HOME: xdg.string,
  };

  const proc = await new Deno.Command("bash", {
    args: ["-c", `${shellcode(env)}\ncd "${sub}"`],
    env,
    stdout: "piped",
    stderr: "piped",
  }).output();

  const stdout = new TextDecoder().decode(proc.stdout);
  const stderr = new TextDecoder().decode(proc.stderr);
  const dev_args = log.isFile()
    ? Deno.readTextFileSync(log.string).split("\n").filter(Boolean)
    : [];

  assert(
    stdout.includes("HOOK_OK"),
    `hook should eval dev's stdout. stdout=${stdout} stderr=${stderr}`,
  );
  assertEquals(stderr, "", "hook should produce no stderr");
  assertEquals(
    dev_args,
    [proj.string],
    "dev must be invoked with the activated dir, not bare",
  );
});

Deno.test("datadir respects XDG_DATA_HOME", () => {
  assertEquals(
    datadir({ XDG_DATA_HOME: "/tmp/xdg-test" }).string,
    "/tmp/xdg-test/pkgx/dev",
  );
});
