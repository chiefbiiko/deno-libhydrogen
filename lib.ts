const VERSION: string = "v0.2.1";

// NOTE: 2 debug/test local libs set env var DENO_PLUGINS to a directory
// containg a shared lib for your os
const DENO_PLUGINS: undefined | string = Deno.env().DENO_PLUGINS;

const DEFAULT_DENO_PLUGINS: string = ".deno_plugins";

const PLUGIN_NAME: string = (Deno.build.os === "win" ? "" : "lib") +
  "deno_libhydrogen" + (Deno.build.os === "win"
    ? ".dll"
    : Deno.build.os === "mac" ? ".dylib" : ".so");

const REMOTE: string =
  `https://github.com/chiefbiiko/deno-libhydrogen/releases/download/${VERSION}/${PLUGIN_NAME}`;

function exists(file: string): boolean {
  try {
    Deno.statSync(file);

    return true;
  } catch (err) {
    if (err.name === "NotFound") {
      return false;
    } else {
      throw err;
    }
  }
}

async function locateLib(): Promise<string> {
  let local: string = "";

  if (DENO_PLUGINS) {
    local = [
      DENO_PLUGINS,
      DENO_PLUGINS.endsWith("/") ? "" : "/",
      PLUGIN_NAME
    ].join("");
  } else {
    local = `${DEFAULT_DENO_PLUGINS}/${PLUGIN_NAME}`;

    if (!exists(local)) {
      const response: Response = await fetch(REMOTE);

      if (!response.ok) {
        throw Error(`unable to locate plugin @ ${REMOTE}`);
      }

      const arr_buf: ArrayBuffer = await response.arrayBuffer();

      // NOTE: recursive 2 not reject if DEFAULT_DENO_PLUGINS already exists
      await Deno.mkdir(DEFAULT_DENO_PLUGINS, { recursive: true });
      await Deno.writeFile(local, new Uint8Array(arr_buf));
    }
  }

  return local;
}

export const plugin: Deno.Plugin = Deno.openPlugin(await locateLib());
