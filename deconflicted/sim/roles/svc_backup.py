"""svc-backup (service): backup.exe in the 01:00 to 01:30 window, SMB to file-01, SSH and rsync on bak-01."""
from __future__ import annotations

from datetime import date, timedelta

from . import common as c

ACTOR = "svc-backup"
BACKUP = "C:/Program Files/Backup/backup.exe"


def timed(day: date, seed: int) -> list[c.Line]:
    rng = c.rng_for(day, seed, ACTOR)
    bak_ip, file_ip = c.ip_of("bak-01"), c.ip_of("file-01")
    begin = c.at(day, 1, 0) + timedelta(seconds=rng.randint(0, 240), milliseconds=rng.randint(0, 999))
    lines = [
        c.syslog(begin - timedelta(seconds=2), "bak-01", "sshd",
                 f"Accepted publickey for svc-backup from {file_ip} port {rng.randint(30000, 60000)} ssh2",
                 pid=rng.randint(1000, 9999)),
        c.win_proc(begin, "bak-01", ACTOR, BACKUP, c.SERVICES, "backup.exe --job nightly"),
        c.syslog(begin + timedelta(seconds=30), "bak-01", "sudo",
                 f" svc-backup : TTY=pts/0 ; PWD=/home/svc-backup ; USER=root ; COMMAND=/usr/bin/rsync -a /srv/share /backup"),
    ]
    when = begin + timedelta(seconds=45)
    for _ in range(rng.randint(6, 10)):  # backup reads the admin share on file-01
        lines.append(c.win_share(when, "file-01", ACTOR, bak_ip, "C$"))
        lines.append(c.flow(when, bak_ip, file_ip, 445, rng.randint(2_000_000, 90_000_000), rng.randint(1500, 60000)))
        when += timedelta(seconds=rng.randint(60, 150), milliseconds=rng.randint(0, 999))
    return c.finish(lines)



def lines_for_day(day: date, seed: int) -> list[tuple[str, str]]:
    return c.strip(timed(day, seed))
