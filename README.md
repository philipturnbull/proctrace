proctrace
=========

A simple tool for process tracing using Linux's `NETLINK_CONNECTOR` interface.
`NETLINK_CONNECTOR` requires privileges so is installed with `cap_net_admin`
capabilities. Capabilities are automatically dropped and a seccomp filter are
installed before executing the child process:

    $ make
    gcc -Werror -Wall -std=c99 -o proctrace main.c -lcap
    $ sudo setcap cap_net_admin+ep ./proctrace
    $ getcap ./proctrace
    ./proctrace = cap_net_admin+ep
    $ ./proctrace /usr/bin/gnome-terminal
    fork pid=23065/tgid=23065 -> pid=23066/tgid=23066
    exec pid=23066/tgid=23066
    fork pid=23065/tgid=23065 -> pid=23067/tgid=23066
    fork pid=23066/tgid=23066 -> pid=23068/tgid=23068
    exec pid=23068/tgid=23068
    comm pid=23067/tgid=23066: 'gmain'
    fork pid=23068/tgid=23068 -> pid=23069/tgid=23069
    exec pid=23069/tgid=23069
    exit pid=23069/tgid=23069
    fork pid=23066/tgid=23066 -> pid=23070/tgid=23068
    fork pid=23066/tgid=23066 -> pid=23071/tgid=23068
    comm pid=23071/tgid=23068: 'gdbus'
    fork pid=22734/tgid=22734 -> pid=23072/tgid=23072
    comm pid=23070/tgid=23068: 'gmain'
    fork pid=23072/tgid=23072 -> pid=23073/tgid=23073
    exec pid=23073/tgid=23073
    fork pid=23072/tgid=23072 -> pid=23074/tgid=23073
    fork pid=23072/tgid=23072 -> pid=23075/tgid=23073
    comm pid=23075/tgid=23073: 'gdbus'
    comm pid=23074/tgid=23073: 'gmain'
    fork pid=23072/tgid=23072 -> pid=23076/tgid=23073
    exit pid=23072/tgid=23072
    comm pid=23076/tgid=23073: 'dconf worker'
    fork pid=23073/tgid=23073 -> pid=23077/tgid=23077
    gid pid=23077/tgid=23077 -> rgid=1000/egid=43
    exec pid=23077/tgid=23077
    gid pid=23077/tgid=23077 -> rgid=1000/egid=1000
    gid pid=23077/tgid=23077 -> rgid=1000/egid=43
    fork pid=23073/tgid=23073 -> pid=23078/tgid=23078
    session pid=23078/tgid=23078
    exec pid=23078/tgid=23078
    ...
