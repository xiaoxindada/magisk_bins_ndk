#!/usr/bin/env python3
import argparse
import errno
import glob
import multiprocessing
import os
from pathlib import Path
import platform
import sys
import os.path as op
import shutil
import stat
import subprocess
import tarfile
import textwrap
import urllib.request

# Environment checks
if not sys.version_info >= (3, 8):
    error("Requires Python 3.8+")


def parse_props(file):
    props = {}
    with open(file, "r") as f:
        for line in [l.strip(" \t\r\n") for l in f]:
            if line.startswith("#") or len(line) == 0:
                continue
            prop = line.split("=")
            if len(prop) != 2:
                continue
            value = prop[1].strip(" \t\r\n")
            if len(value) == 0:
                continue
            props[prop[0].strip(" \t\r\n")] = value
    return props


def load_config():
    config = {}
    for key, value in parse_props("magisk_config.prop").items():
        if key.startswith("magisk."):
            config[key[7:]] = value
    return config


def error(str):
    print(f"\n\033[41m{str}\033[0m\n")
    sys.exit(1)


def mv(source, target):
    try:
        shutil.move(source, target)
    except:
        pass


def cp(source, target):
    try:
        shutil.copyfile(source, target)
    except:
        pass


def cp_rf(source, target):
    shutil.copytree(source, target, copy_function=cp, dirs_exist_ok=True)


def rm(file):
    try:
        os.remove(file)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


def rm_on_error(func, path, _):
    # Remove a read-only file on Windows will get "WindowsError: [Error 5] Access is denied"
    # Clear the "read-only" and retry
    os.chmod(path, stat.S_IWRITE)
    os.unlink(path)


def rm_rf(path):
    shutil.rmtree(path, ignore_errors=True, onerror=rm_on_error)


def mkdir(path, mode=0o755):
    try:
        os.mkdir(path, mode)
    except:
        pass


def mkdir_p(path, mode=0o755):
    os.makedirs(path, mode, exist_ok=True)


def execv(cmd, env=None):
    return subprocess.run(cmd, stdout=sys.stdout, env=env)


def system(cmd):
    return subprocess.run(cmd, shell=True, stdout=sys.stdout)


def cmd_out(cmd):
    return (
        subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        .stdout.strip()
        .decode("utf-8")
    )


def sed_i(originStr, targetStr, file):
    with open(file, "r", encoding="utf-8") as i:
        with open(f"{file}_tmp", "w", encoding="utf-8") as o:
            for line in i.readlines():
                new_line = line
                if originStr in line:
                    new_line = line.replace(originStr, targetStr)
                o.write(new_line)
    mv(f"{file}_tmp", file)


LOCALDIR = op.realpath(".")
cpu_count = multiprocessing.cpu_count()
os_name = platform.system().lower()
release = True

# Common constants
support_abis = {
    "armeabi-v7a": "thumbv7neon-linux-androideabi",
    "x86": "i686-linux-android",
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
    "riscv64": "riscv64-linux-android",
}

# Environment checks and detection
is_windows = os.name == "nt"
EXE_EXT = ".exe" if is_windows else ""

# Global vars
default_targets = {"magiskboot", "magiskpolicy"}
support_targets = default_targets | {"resetprop"}
rust_targets = {"magisk", "magiskinit", "magiskboot", "magiskpolicy"}
archs = {"armeabi-v7a", "x86", "arm64-v8a", "x86_64"}
config = load_config()
triples = map(support_abis.get, archs)
build_abis = dict(zip(archs, triples))

# Common paths
ndk_root = Path(LOCALDIR, "ndk")
native_root = Path(LOCALDIR, "native")
native_out = native_root / "out"
ndk_build = ndk_root / "ndk-build"
rust_bin = ndk_root / "toolchains" / "rust" / "bin"
llvm_bin = ndk_root / "toolchains" / "llvm" / "prebuilt" / f"{os_name}-x86_64" / "bin"
native_gen_path = native_out / "generated"
rust_out = native_out / "rust"
cargo = ndk_root / "toolchains" / "rust" / "bin" / f"cargo{EXE_EXT}"


def write_if_diff(file_name, text):
    do_write = True
    if op.exists(file_name):
        with open(file_name, "r") as f:
            orig = f.read()
        do_write = orig != text
    if do_write:
        with open(file_name, "w") as f:
            print(f"Write file {file_name}")
            f.write(text)


def dump_flag_header():
    flag_txt = "#pragma once\n"
    flag_txt += f'#define MAGISK_VERSION      "{config["version"]}"\n'
    flag_txt += f'#define MAGISK_VER_CODE     {config["versionCode"]}\n'
    flag_txt += f"#define MAGISK_DEBUG        {0 if release else 1}\n"

    mkdir_p(native_gen_path)
    write_if_diff(native_gen_path / "flags.h", flag_txt)

    rust_flag_txt = f'pub const MAGISK_VERSION: &str = "{config["version"]}";\n'
    rust_flag_txt += f'pub const MAGISK_VER_CODE: i32 = {config["versionCode"]};\n'
    write_if_diff(native_gen_path / "flags.rs", rust_flag_txt)


def build_native():
    # Verify NDK install
    try:
        with open(Path(ndk_root, "ONDK_VERSION"), "r") as ondk_ver:
            assert ondk_ver.read().strip(" \t\r\n") == config["ondkVersion"]
    except:
        error('Unmatched NDK. Please install/upgrade NDK with "build.py --setup_ndk"')

    targets = support_targets
    print("* Building: " + " ".join(targets))

    if sccache := shutil.which("sccache"):
        os.environ["RUSTC_WRAPPER"] = sccache
        os.environ["NDK_CCACHE"] = sccache
        os.environ["CARGO_INCREMENTAL"] = "0"
    if ccache := shutil.which("ccache"):
        os.environ["NDK_CCACHE"] = ccache

    dump_flag_header()
    build_rust_src(targets)
    build_cpp_src(targets)
    clean_build_src()
    with open(Path(native_out, "magisk_version.txt"), "w", encoding="utf-8") as f:
        f.write(f"magisk.versionCode={config['versionCode']}\n")


def build_rust_src(targets: set):
    targets = targets.copy()
    if "resetprop" in targets:
        targets.add("magisk")
    targets = targets & rust_targets

    os.chdir(native_root / "src")

    # Start building the build commands
    cmds = ["build", "-p", ""]
    if release:
        cmds.append("-r")
        profile = "release"
    else:
        profile = "debug"

    for triple in build_abis.values():
        cmds.append("--target")
        cmds.append(triple)

    for tgt in targets:
        cmds[2] = tgt
        proc = run_cargo(cmds)
        if proc.returncode != 0:
            error("Build rust src failed!")

    os.chdir(Path(LOCALDIR))

    for arch, triple in build_abis.items():
        arch_out = native_out / arch
        arch_out.mkdir(mode=0o755, exist_ok=True)
        for tgt in targets:
            source = rust_out / triple / profile / f"lib{tgt}.a"
            target = arch_out / f"lib{tgt}-rs.a"
            mv(source, target)


def build_cpp_src(targets: set):
    cmds = []
    clean = False

    if "magisk" in targets:
        cmds.append("B_MAGISK=1")
        clean = True

    if "magiskpolicy" in targets:
        cmds.append("B_POLICY=1")
        clean = True

    if "magiskinit" in targets:
        cmds.append("B_PRELOAD=1")

    if "resetprop" in targets:
        cmds.append("B_PROP=1")

    if cmds:
        run_ndk_build(cmds)

    cmds.clear()

    if "magiskinit" in targets:
        cmds.append("B_INIT=1")

    if "magiskboot" in targets:
        cmds.append("B_BOOT=1")

    if cmds:
        cmds.append("B_CRT0=1")
        run_ndk_build(cmds)

    if clean:
        clean_elf()


def clean_elf():
    cargo_toml = Path(LOCALDIR, "tools", "elf-cleaner", "Cargo.toml")
    cmds = ["run", "--release", "--manifest-path", cargo_toml]
    cmds.append("--")
    if "magisk" in default_targets:
        cmds.extend(glob.glob("out/*/magisk"))
    if "magiskpolicy" in default_targets:
        cmds.extend(glob.glob("out/*/magiskpolicy"))
    run_cargo(cmds)


def clean_build_src():
    rm_rf(rust_out)
    rm_rf(native_gen_path)
    libinit_lds = [l for l in glob.glob("out/*/libinit-ld*")]
    for libinit_ld in libinit_lds:
        rm(libinit_ld)


def setup_ndk():
    ondk_version = config["ondkVersion"]
    url = f"https://github.com/topjohnwu/ondk/releases/download/{ondk_version}/ondk-{ondk_version}-{os_name}.tar.xz"
    ndk_archive = url.split("/")[-1]
    ondk_path = Path(LOCALDIR, f"ondk-{ondk_version}")

    if (
        not op.exists(ndk_archive)
        and not op.exists(ndk_root)
        or op.exists(ndk_root)
        and open(Path(ndk_root, "ONDK_VERSION")).read().strip(" \t\r\n") != ondk_version
    ):
        print(f"Downloading and extracting {ndk_archive}")
        with urllib.request.urlopen(url) as response:
            with tarfile.open(mode="r|xz", fileobj=response) as tar:
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(LOCALDIR, filter="tar")
                else:
                    tar.extractall(LOCALDIR)
    elif op.exists(ndk_archive):
        print(f"Extracting {ndk_archive}")
        with tarfile.open(ndk_archive, mode="r|xz") as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(LOCALDIR, filter="tar")
            else:
                tar.extractall(LOCALDIR)

    rm_rf(ndk_root)
    mv(ondk_path, ndk_root)


def run_ndk_build(cmds: list):
    os.chdir(native_root)
    cmds.append("NDK_PROJECT_PATH=.")
    cmds.append("NDK_APPLICATION_MK=src/Application.mk")
    cmds.append(f"APP_ABI={' '.join(build_abis.keys())}")
    cmds.append(f"-j{cpu_count}")
    if not release:
        cmds.append("MAGISK_DEBUG=1")
    proc = execv([ndk_build, *cmds])
    if proc.returncode != 0:
        error("Build binary failed!")
    move_gen_bins()


def move_gen_bins():
    os.chdir(native_root)
    for arch in build_abis.keys():
        arch_dir = Path("libs", arch)
        out_dir = Path(native_out, arch)
        for source in arch_dir.iterdir():
            target = out_dir / source.name
            mv(source, target)
            rm(Path(out_dir, f"lib{source.name}-rs.a"))


def run_cargo(cmds):
    env = os.environ.copy()
    env["PATH"] = f'{rust_bin}{os.pathsep}{env["PATH"]}'
    env["CARGO_BUILD_RUSTC"] = str(rust_bin / f"rustc{EXE_EXT}")
    env["CARGO_BUILD_RUSTFLAGS"] = f"-Z threads={cpu_count}"
    return execv([cargo, *cmds], env)


def update_code():
    os.chdir(LOCALDIR)
    rm_rf("Magisk")
    rm_rf("native")
    rm_rf("tools")
    if (
        system(
            "git clone --recurse-submodules https://github.com/topjohnwu/Magisk.git Magisk"
        ).returncode
        != 0
    ):
        error("git clone failed!")

    # Generate magisk_config.prop
    magisk_version = cmd_out(f"cd Magisk && git rev-parse --short=8 HEAD && cd ..").strip(" \t\r\n")
    ondk_version = None
    with open(Path("Magisk", "app", "gradle.properties"), "r") as i:
        with open(Path("Magisk", "build.py"), "r") as b:
            with open(Path("magisk_config.prop"), "w", encoding="utf-8") as o:
                for line in i.readlines()[-3:]:
                    o.write(line)
                o.write(f"magisk.version={magisk_version}\n")
                for line in b.readlines():
                    if "ondk_version" in line:
                        ondk_version = line.split("=")[1].replace(" ", "").replace('"', '')
                        break
                o.write(f"magisk.ondkVersion={ondk_version}\n")

    mv(Path("Magisk", "native"), "native")
    mv(Path("Magisk", "tools"), "tools")
    rm_rf("Magisk")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Magiskboot build and update code script"
    )
    parser.add_argument("--setup_ndk", action="store_true", help="Update and setup ndk")
    parser.add_argument("--build_binary", action="store_true", help="Build binary")
    parser.add_argument("--update_code", action="store_true", help="Update magisk code")
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()

    if args.setup_ndk:
        setup_ndk()

    if args.build_binary:
        build_native()

    if args.update_code:
        update_code()
