{
    "targets": [
        {
            "target_name": "sockdestroy",
            "sources": ["src/netlink.c", "src/sock_destroy.c", "src/addon.c"],
            "include_dirs": [],
            "defines": ["NAPI_VERSION=9", "_GNU_SOURCE"],
            "cflags": [
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wno-unused-parameter",
                "-O2",
                "-U_FORTIFY_SOURCE",
                "-D_FORTIFY_SOURCE=3",
                "-fstack-protector-strong",
                "-Wformat=2",
                "-Werror=format-security",
                "-fvisibility=hidden"
            ],
            "ldflags": ["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack","-Wl,-z,defs","-Wl,--as-needed"],
            "conditions": [["OS!='linux'", {"defines": ["UNSUPPORTED_PLATFORM"]}]],
        }
    ]
}
