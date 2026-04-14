#!/usr/bin/env python3
import sys

sys.dont_write_bytecode = True
from env import *
import argparse
import errno
import glob
import os
import sys
import os.path as op
import shutil
import stat
import subprocess
import tarfile
import urllib.request


def error(str: str):
    print(f"\n\033[41m{str}\033[0m\n")
    sys.exit(1)


def mv(source: Path, target: Path):
    try:
        shutil.move(source, target)
    except:
        pass


def cp(source: Path, target: Path):
    try:
        shutil.copyfile(source, target)
    except:
        pass


def cp_rf(source: Path, target: Path):
    shutil.copytree(source, target, copy_function=cp, dirs_exist_ok=True)


def rm(file: Path):
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


def rm_rf(path: Path):
    shutil.rmtree(path, ignore_errors=True, onerror=rm_on_error)


def mkdir(path, mode=0o755):
    try:
        os.mkdir(path, mode)
    except:
        pass


def mkdir_p(path: Path, mode=0o755):
    os.makedirs(path, mode, exist_ok=True)


def execv(cmds: list):
    out = sys.stdout
    # Use shell on Windows to support PATHEXT
    return subprocess.run(cmds, stdout=out, shell=is_windows)


def system(cmds: list):
    return subprocess.run(cmds, shell=True, stdout=sys.stdout)


def cmd_out(cmds: list):
    return (
        subprocess.run(
            cmds, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
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


release = True
# Common constants
support_abis = {
    "armeabi-v7a": "thumbv7neon-linux-androideabi",
    "x86": "i686-linux-android",
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
    "riscv64": "riscv64-linux-android",
}


# Global vars
default_targets = {"magiskboot", "magiskpolicy"}
support_targets = default_targets | {"resetprop"}
rust_targets = {"magisk", "magiskinit", "magiskboot", "magiskpolicy"}
archs = {"armeabi-v7a", "x86", "arm64-v8a", "x86_64"}
triples = map(support_abis.get, archs)
build_abis = dict(zip(archs, triples))
config = load_config()

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

    mkdir_p(paths().native_gen)
    write_if_diff(paths().native_gen / "flags.h", flag_txt)

    rust_flag_txt = f'pub const MAGISK_VERSION: &str = "{config["version"]}";\n'
    rust_flag_txt += f'pub const MAGISK_VER_CODE: i32 = {config["versionCode"]};\n'
    write_if_diff(paths().native_gen / "flags.rs", rust_flag_txt)


def build_native():
    ensure_toolchain()

    targets = support_targets
    print("* Building: " + " ".join(targets))
    dump_flag_header()
    build_rust_src(targets)
    build_cpp_src(targets)
    clean_build_src()
    with open(paths().native_out / "magisk_version.txt", "w", encoding="utf-8") as f:
        f.write(f"magisk.versionCode={config['versionCode']}\n")


def build_rust_src(targets: set):
    ensure_cargo()

    targets = targets.copy()
    if "resetprop" in targets:
        targets.add("magisk")
    targets = targets & rust_targets

    os.chdir(paths().native / "src")

    # Start building the build commands
    cmds = ["cargo", "build", "-p", ""]
    if release:
        cmds.append("-r")
        profile = "release"
    else:
        profile = "debug"

    for triple in build_abis.values():
        cmds.append("--target")
        cmds.append(triple)

    for tgt in targets:
        cmds[3] = tgt
        proc = execv(cmds)
        if proc.returncode != 0:
            error("Build rust src failed!")

    os.chdir(paths().project_root)

    for arch, triple in build_abis.items():
        arch_out = paths().native_out / arch
        arch_out.mkdir(mode=0o755, exist_ok=True)
        for tgt in targets:
            source = paths().rust_out / triple / profile / f"lib{tgt}.a"
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
        collect_ndk_build()

    cmds.clear()

    if "magiskinit" in targets:
        cmds.append("B_INIT=1")

    if "magiskboot" in targets:
        cmds.append("B_BOOT=1")

    if cmds:
        cmds.append("B_CRT0=1")
        run_ndk_build(cmds)
        collect_ndk_build()

    if clean:
        clean_elf()


def clean_elf():
    ensure_cargo()

    os.chdir(paths().native)
    cargo_toml = paths().project_root / "tools" / "elf-cleaner" / "Cargo.toml"
    cmds = ["cargo", "run", "--release", "--manifest-path", cargo_toml]
    cmds.append("--")
    if "magisk" in default_targets:
        cmds.extend(glob.glob("out/*/magisk"))
    if "magiskpolicy" in default_targets:
        cmds.extend(glob.glob("out/*/magiskpolicy"))
    execv(cmds)


def clean_build_src():
    rm_rf(paths().rust_out)
    rm_rf(paths().native_gen)
    os.chdir(paths().native)
    libinit_lds = [l for l in glob.glob("out/*/libinit-ld*")]
    for libinit_ld in libinit_lds:
        rm(libinit_ld)
    staticlibs = [l for l in glob.glob("out/*/*.a")]
    for lib in staticlibs:
        rm(lib)


def setup_ndk():
    url = f"https://github.com/topjohnwu/ondk/releases/download/{ondk_version}/ondk-{ondk_version}-{os_name}.tar.xz"
    ndk_archive = url.split("/")[-1]
    ondk_path = paths().project_root / f"ondk-{ondk_version}"

    if (
        not op.exists(ndk_archive)
        and not op.exists(paths().ndk)
        or op.exists(paths().ndk)
        and open(paths().ndk / "ONDK_VERSION").read().strip(" \t\r\n") != ondk_version
    ):
        print(f"Downloading and extracting {ndk_archive}")
        with urllib.request.urlopen(url) as response:
            with tarfile.open(mode="r|xz", fileobj=response) as tar:
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(paths().project_root, filter="tar")
                else:
                    tar.extractall(paths().project_root)
    elif op.exists(ndk_archive):
        print(f"Extracting {ndk_archive}")
        with tarfile.open(ndk_archive, mode="r|xz") as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(paths().project_root, filter="tar")
            else:
                tar.extractall(paths().project_root)

    rm_rf(paths().ndk)
    mv(ondk_path, paths().ndk)


def collect_ndk_build():
    for arch in build_abis.keys():
        arch_dir = paths().native / "libs" / arch
        out_dir = paths().native / "out" / arch
        for source in arch_dir.iterdir():
            target = out_dir / source.name
            mv(source, target)


def run_ndk_build(cmds: list):
    os.chdir(paths().native)
    cmds.append(f"NDK_PROJECT_PATH=.")
    cmds.append(f"NDK_APPLICATION_MK=src/Application.mk")
    cmds.append(f"APP_ABI={' '.join(build_abis.keys())}")
    cmds.append(f"-j{min(8, cpu_count)}")
    if not release:
        cmds.append("MAGISK_DEBUG=1")
    proc = execv([paths().ndk_build, *cmds])
    if proc.returncode != 0:
        error("Build binary failed!")
    os.chdir(paths().project_root)



def update_code():
    os.chdir(paths().project_root)
    rm_rf(paths().project_root / "Magisk")
    rm_rf(paths().project_root / "native")
    rm_rf(paths().project_root / "tools")
    if (
        system(
            "git clone --recurse-submodules https://github.com/topjohnwu/Magisk.git Magisk"
        ).returncode
        != 0
    ):
        error("git clone failed!")

    # Generate magisk_config.prop
    magisk_version = cmd_out(
        "cd Magisk && git rev-parse --short=8 HEAD && cd .."
    ).strip(" \t\r\n")
    ondk_version = None
    with open(paths().project_root / "Magisk" / "app" / "gradle.properties", "r") as i:
        with open(paths().project_root / "Magisk" / "scripts" / "env.py", "r") as b:
            with open(
                paths().project_root / "magisk_config.prop", "w", encoding="utf-8"
            ) as o:
                for line in i.readlines()[-3:]:
                    o.write(line)
                o.write(f"magisk.version={magisk_version}\n")
                for line in b.readlines():
                    if "ondk_version" in line:
                        ondk_version = (
                            line.split("=")[1].replace(" ", "").replace('"', "")
                        )
                        break
                o.write(f"magisk.ondkVersion={ondk_version}\n")

    mv(paths().project_root / "Magisk" / "native", paths().project_root / "native")
    mv(paths().project_root / "Magisk" / "tools", paths().project_root / "tools")
    rm_rf(paths().project_root / "Magisk")


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
