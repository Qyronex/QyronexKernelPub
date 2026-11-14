// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_linux_abi::{
    Errno, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_net::{MAX_SCM_RIGHTS_FDS, SCM_RIGHTS, SOL_SOCKET, SockAddr, SocketTable, Ucred};
use kernal_usercopy::Error as UsercopyError;

/// Dedicated file-descriptor base for Step-34 sockets (`128..160`), partitioned cleanly above
/// `STEP29_RUNTIME_FDS` (`0..32`), `DEV_FD_BASE` (`64..96`), and `PROC_SYS_FD_BASE` (`96..128`).
pub(super) const SOCK_FD_BASE: i32 = 128;
const MAX_SOCKETS: usize = 16;
const SOCK_BUF_CAP: usize = 512;
const MAX_SOCKADDR_BYTES: usize = 110;
const ARM64_STAT_BYTES: usize = 128;
const S_IFSOCK_MODE: u32 = 0o140_777;

struct Step34NetCell {
    state: AtomicU8,
    value: UnsafeCell<SocketTable<MAX_SOCKETS, SOCK_BUF_CAP>>,
}

// SAFETY: access is serialized by the atomic state transition (`0 -> 1 -> 0`) inside the IRQ-masked
// synchronous lower-EL trap window.
unsafe impl Sync for Step34NetCell {}

static NET_STATE: Step34NetCell = Step34NetCell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(SocketTable::new()),
};

fn with_net_state<R>(
    f: impl FnOnce(&mut SocketTable<MAX_SOCKETS, SOCK_BUF_CAP>) -> R,
) -> Result<R, ()> {
    if NET_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state transition `0 -> 1` grants exclusive mutable access for this synchronous scope.
    let result = f(unsafe { &mut *NET_STATE.value.get() });
    NET_STATE.state.store(0, Ordering::Release);
    Ok(result)
}

/// Returns `true` if `raw_fd` lies in the Step-34 socket descriptor window (`128..144`).
pub(super) const fn is_socket_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= SOCK_FD_BASE && fd < SOCK_FD_BASE + (MAX_SOCKETS as i32)
}

/// Returns `true` if `raw_fd` is a readable Step-34 socket (used by Step-35 `epoll_wait`).
pub(super) fn socket_has_readable_data(raw_fd: u64) -> bool {
    if !is_socket_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - SOCK_FD_BASE) as usize;
    with_net_state(|table| table.has_readable_data(idx)).unwrap_or(false)
}

/// Dispatches Step-34 socket syscalls and socket file-descriptor operations (`close`, `read`,
/// `write`, `fstat`, `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`, `connect`,
/// `getsockname`, `getpeername`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `shutdown`,
/// `sendmsg`, `recvmsg`).
pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // close(fd)
        57 if is_socket_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // read(fd, buf, count)
        63 if is_socket_fd(request.args[0]) => Ok(Some(encode_result(handle_recvfrom(
            request.args[0],
            request.args[1],
            request.args[2],
            0,
            0,
        )?))),
        // write(fd, buf, count)
        64 if is_socket_fd(request.args[0]) => Ok(Some(encode_result(handle_sendto(
            request.args[0],
            request.args[1],
            request.args[2],
            0,
            0,
        )?))),
        // fstat(fd, statbuf)
        80 if is_socket_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        // socket(domain, type, protocol)
        198 => Ok(Some(encode_result(handle_socket(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // socketpair(domain, type, protocol, sv)
        199 => Ok(Some(encode_result(handle_socketpair(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        // bind(sockfd, addr, addrlen)
        200 => Ok(Some(encode_result(handle_bind(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // listen(sockfd, backlog)
        201 => Ok(Some(encode_result(handle_listen(
            request.args[0],
            request.args[1],
        )?))),
        // accept(sockfd, addr, addrlen)
        202 => Ok(Some(encode_result(handle_accept4(
            request.args[0],
            request.args[1],
            request.args[2],
            0,
        )?))),
        // connect(sockfd, addr, addrlen)
        203 => Ok(Some(encode_result(handle_connect(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // getsockname(sockfd, addr, addrlen)
        204 => Ok(Some(encode_result(handle_getsockname(
            request.args[0],
            request.args[1],
            request.args[2],
            false,
        )?))),
        // getpeername(sockfd, addr, addrlen)
        205 => Ok(Some(encode_result(handle_getsockname(
            request.args[0],
            request.args[1],
            request.args[2],
            true,
        )?))),
        // sendto(sockfd, buf, len, flags, dest_addr, addrlen)
        206 => Ok(Some(encode_result(handle_sendto(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[4],
            request.args[5],
        )?))),
        // recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
        207 => Ok(Some(encode_result(handle_recvfrom(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[4],
            request.args[5],
        )?))),
        // setsockopt(sockfd, level, optname, optval, optlen)
        208 => Ok(Some(encode_result(handle_setsockopt(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        )?))),
        // getsockopt(sockfd, level, optname, optval, optlen)
        209 => Ok(Some(encode_result(handle_getsockopt(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        )?))),
        // shutdown(sockfd, how)
        210 => Ok(Some(encode_result(handle_shutdown(
            request.args[0],
            request.args[1],
        )?))),
        // sendmsg(sockfd, msg, flags)
        211 => Ok(Some(encode_result(handle_sendmsg(
            request.args[0],
            request.args[1],
        )?))),
        // recvmsg(sockfd, msg, flags)
        212 => Ok(Some(encode_result(handle_recvmsg(
            request.args[0],
            request.args[1],
        )?))),
        // accept4(sockfd, addr, addrlen, flags)
        242 => Ok(Some(encode_result(handle_accept4(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        )?))),
        _ => Ok(None),
    }
}

fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

fn socket_index(raw_fd: u64) -> Result<usize, Errno> {
    let fd = linux_signed_int(raw_fd);
    if fd < 0 {
        return Err(Errno::EBADF);
    }
    if !is_socket_fd(raw_fd) {
        return Err(Errno::ENOTSOCK);
    }
    Ok((fd - SOCK_FD_BASE) as usize)
}

fn current_ucred() -> Ucred {
    let mut cred = Ucred::ROOT_INIT;
    let current_cpu = super::super::current_cpu_index();
    if let Some(scheduler) = super::super::CPU_SCHEDULERS.get(current_cpu) {
        // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
        if let Ok(current) = unsafe { scheduler.bootstrap_current_global_thread() } {
            let _ = super::runtime::with_linux_runtime(|state| {
                let _ = state.with_current_process_identity(current, |proc_ref, identities| {
                    if let Ok(p) = identities.bound_pid(proc_ref) {
                        cred.pid = p.get();
                    }
                });
                let _ = state.with_current_process_credentials(current, |creds| {
                    cred.uid = creds.euid();
                    cred.gid = creds.egid();
                });
            });
        }
    }
    cred
}

fn handle_socket(raw_domain: u64, raw_type: u64, raw_proto: u64) -> Result<Result<i64, Errno>, ()> {
    let Ok(domain) = u16::try_from(linux_unsigned_int(raw_domain)) else {
        return Ok(Err(Errno::EAFNOSUPPORT));
    };
    let sock_type = linux_unsigned_int(raw_type);
    let proto = linux_unsigned_int(raw_proto);
    with_net_state(|table| {
        let idx = table.socket(domain, sock_type, proto)?;
        Ok(i64::from(SOCK_FD_BASE + (idx as i32)))
    })
}

fn handle_socketpair(
    raw_domain: u64,
    raw_type: u64,
    raw_proto: u64,
    user_sv: u64,
) -> Result<Result<i64, Errno>, ()> {
    if user_sv == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let Ok(domain) = u16::try_from(linux_unsigned_int(raw_domain)) else {
        return Ok(Err(Errno::EAFNOSUPPORT));
    };
    let sock_type = linux_unsigned_int(raw_type);
    let proto = linux_unsigned_int(raw_proto);
    let cred = current_ucred();
    let pair = with_net_state(|table| table.socketpair(domain, sock_type, proto, cred))?;
    let (a, b) = match pair {
        Ok(p) => p,
        Err(errno) => return Ok(Err(errno)),
    };
    let mut sv_bytes = [0u8; 8];
    sv_bytes[0..4].copy_from_slice(&(SOCK_FD_BASE + (a as i32)).to_le_bytes());
    sv_bytes[4..8].copy_from_slice(&(SOCK_FD_BASE + (b as i32)).to_le_bytes());
    if let Err(errno) = copy_to_user(user_sv, &sv_bytes) {
        with_net_state(|table| {
            let _ = table.close(a);
            let _ = table.close(b);
        })?;
        return Ok(Err(errno));
    }
    Ok(Ok(0))
}

fn handle_bind(raw_fd: u64, user_addr: u64, addrlen: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let addr = match read_user_sockaddr(user_addr, addrlen) {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    with_net_state(|table| table.bind(idx, addr).map(|()| 0))
}

fn handle_listen(raw_fd: u64, raw_backlog: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let backlog = linux_signed_int(raw_backlog);
    with_net_state(|table| table.listen(idx, backlog).map(|()| 0))
}

fn handle_connect(raw_fd: u64, user_addr: u64, addrlen: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let addr = match read_user_sockaddr(user_addr, addrlen) {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    let cred = current_ucred();
    with_net_state(|table| table.connect(idx, addr, cred).map(|()| 0))
}

fn handle_accept4(
    raw_fd: u64,
    user_addr: u64,
    user_addrlen: u64,
    raw_flags: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let flags = linux_unsigned_int(raw_flags);
    let accepted = with_net_state(|table| table.accept4(idx, flags))?;
    let (new_idx, peer_addr) = match accepted {
        Ok(pair) => pair,
        Err(e) => return Ok(Err(e)),
    };
    if user_addr != 0 {
        if let Some(addr) = peer_addr
            && let Err(e) = write_user_sockaddr(user_addr, user_addrlen, &addr)
        {
            return Ok(Err(e));
        }
    }
    Ok(Ok(i64::from(SOCK_FD_BASE + (new_idx as i32))))
}

fn handle_getsockname(
    raw_fd: u64,
    user_addr: u64,
    user_addrlen: u64,
    peer: bool,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let res = with_net_state(|table| {
        if peer {
            table.getpeername(idx)
        } else {
            table.getsockname(idx)
        }
    })?;
    let addr = match res {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = write_user_sockaddr(user_addr, user_addrlen, &addr) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn handle_sendto(
    raw_fd: u64,
    user_buf: u64,
    len: u64,
    user_dest: u64,
    addrlen: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let dest = if user_dest != 0 {
        match read_user_sockaddr(user_dest, addrlen) {
            Ok(a) => Some(a),
            Err(e) => return Ok(Err(e)),
        }
    } else {
        None
    };
    let take = usize::try_from(len)
        .unwrap_or(SOCK_BUF_CAP)
        .min(SOCK_BUF_CAP);
    let mut buf = [0u8; SOCK_BUF_CAP];
    if take > 0 {
        if let Err(e) = copy_from_user(&mut buf[..take], user_buf) {
            return Ok(Err(e));
        }
    }
    with_net_state(|table| {
        table
            .send(idx, &buf[..take], dest, &[])
            .map(|sent| sent as i64)
    })
}

fn handle_recvfrom(
    raw_fd: u64,
    user_buf: u64,
    len: u64,
    user_src: u64,
    user_addrlen: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let take = usize::try_from(len)
        .unwrap_or(SOCK_BUF_CAP)
        .min(SOCK_BUF_CAP);
    if take > 0 && user_buf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut buf = [0u8; SOCK_BUF_CAP];
    let recv_res = with_net_state(|table| table.recv(idx, &mut buf[..take]))?;
    let (n, peer_addr, _, _) = match recv_res {
        Ok(t) => t,
        Err(e) => return Ok(Err(e)),
    };
    if n > 0 {
        if let Err(e) = copy_to_user(user_buf, &buf[..n]) {
            return Ok(Err(e));
        }
    }
    if user_src != 0
        && let Some(addr) = peer_addr
        && let Err(e) = write_user_sockaddr(user_src, user_addrlen, &addr)
    {
        return Ok(Err(e));
    }
    Ok(Ok(n as i64))
}

fn handle_setsockopt(
    raw_fd: u64,
    raw_level: u64,
    raw_optname: u64,
    user_optval: u64,
    optlen: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if optlen < 4 || user_optval == 0 {
        return Ok(Err(Errno::EINVAL));
    }
    let mut raw_val = [0u8; 4];
    if let Err(e) = copy_from_user(&mut raw_val, user_optval) {
        return Ok(Err(e));
    }
    let val = u32::from_le_bytes(raw_val);
    let level = linux_unsigned_int(raw_level);
    let optname = linux_unsigned_int(raw_optname);
    with_net_state(|table| table.setsockopt(idx, level, optname, val).map(|()| 0))
}

fn handle_getsockopt(
    raw_fd: u64,
    raw_level: u64,
    raw_optname: u64,
    user_optval: u64,
    user_optlen: u64,
) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if user_optval == 0 || user_optlen == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut len_bytes = [0u8; 4];
    if let Err(e) = copy_from_user(&mut len_bytes, user_optlen) {
        return Ok(Err(e));
    }
    let max_len = (u32::from_le_bytes(len_bytes) as usize).min(32);
    let mut out = [0u8; 32];
    let level = linux_unsigned_int(raw_level);
    let optname = linux_unsigned_int(raw_optname);
    let res = with_net_state(|table| table.getsockopt(idx, level, optname, &mut out[..max_len]))?;
    let written = match res {
        Ok(w) => w,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = copy_to_user(user_optval, &out[..written]) {
        return Ok(Err(e));
    }
    if let Err(e) = copy_to_user(user_optlen, &(written as u32).to_le_bytes()) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn handle_shutdown(raw_fd: u64, raw_how: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let how = linux_unsigned_int(raw_how);
    with_net_state(|table| table.shutdown(idx, how).map(|()| 0))
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_net_state(|table| table.close(idx).map(|()| 0))
}

fn handle_fstat(raw_fd: u64, user_statbuf: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if user_statbuf == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let valid = with_net_state(|table| table.getsockname(idx).is_ok())?;
    if !valid {
        return Ok(Err(Errno::EBADF));
    }
    let mut stat = [0u8; ARM64_STAT_BYTES];
    stat[8..16].copy_from_slice(&((idx as u64) + 1000).to_le_bytes()); // st_ino
    stat[16..20].copy_from_slice(&S_IFSOCK_MODE.to_le_bytes()); // st_mode = S_IFSOCK | 0777
    stat[20..24].copy_from_slice(&1u32.to_le_bytes()); // st_nlink = 1
    stat[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
    if let Err(e) = copy_to_user(user_statbuf, &stat) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn handle_sendmsg(raw_fd: u64, user_msghdr: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if user_msghdr == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    // AArch64 struct msghdr (56 bytes):
    // 0..8: msg_name, 8..12: msg_namelen, 16..24: msg_iov, 24..32: msg_iovlen,
    // 32..40: msg_control, 40..48: msg_controllen, 48..52: msg_flags
    let mut hdr = [0u8; 56];
    if let Err(e) = copy_from_user(&mut hdr, user_msghdr) {
        return Ok(Err(e));
    }
    let msg_name = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let msg_namelen = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64;
    let msg_iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let msg_iovlen = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let msg_control = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let msg_controllen = u64::from_le_bytes(hdr[40..48].try_into().unwrap());

    if msg_iovlen > 16 {
        return Ok(Err(Errno::EMSGSIZE));
    }
    let dest = if msg_name != 0 && msg_namelen > 0 {
        match read_user_sockaddr(msg_name, msg_namelen) {
            Ok(a) => Some(a),
            Err(e) => return Ok(Err(e)),
        }
    } else {
        None
    };

    let mut payload = [0u8; SOCK_BUF_CAP];
    let mut total_len = 0usize;
    for i in 0..(msg_iovlen as usize) {
        let mut iov = [0u8; 16];
        let Some(iov_addr) = msg_iov.checked_add((i * 16) as u64) else {
            return Ok(Err(Errno::EFAULT));
        };
        if let Err(e) = copy_from_user(&mut iov, iov_addr) {
            return Ok(Err(e));
        }
        let base = u64::from_le_bytes(iov[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(iov[8..16].try_into().unwrap()) as usize;
        let take = len.min(SOCK_BUF_CAP.saturating_sub(total_len));
        if take > 0 {
            if let Err(e) = copy_from_user(&mut payload[total_len..total_len + take], base) {
                return Ok(Err(e));
            }
            total_len += take;
        }
    }

    let mut rights = [0i32; MAX_SCM_RIGHTS_FDS];
    let mut rights_count = 0usize;
    if msg_control != 0 && msg_controllen >= 16 {
        // AArch64 struct cmsghdr (16 bytes): cmsg_len(u64), cmsg_level(i32), cmsg_type(i32)
        let mut cmsg = [0u8; 16 + MAX_SCM_RIGHTS_FDS * 4];
        let copy_len = (msg_controllen as usize).min(cmsg.len());
        if let Err(e) = copy_from_user(&mut cmsg[..copy_len], msg_control) {
            return Ok(Err(e));
        }
        let cmsg_len = u64::from_le_bytes(cmsg[0..8].try_into().unwrap()) as usize;
        let cmsg_level = i32::from_le_bytes(cmsg[8..12].try_into().unwrap());
        let cmsg_type = i32::from_le_bytes(cmsg[12..16].try_into().unwrap());
        if cmsg_level == (SOL_SOCKET as i32) && cmsg_type == SCM_RIGHTS && cmsg_len >= 16 {
            let data_bytes = cmsg_len.min(copy_len) - 16;
            rights_count = (data_bytes / 4).min(MAX_SCM_RIGHTS_FDS);
            for (r_idx, slot) in rights.iter_mut().enumerate().take(rights_count) {
                let off = 16 + r_idx * 4;
                *slot = i32::from_le_bytes(cmsg[off..off + 4].try_into().unwrap());
            }
        }
    }

    with_net_state(|table| {
        table
            .send(idx, &payload[..total_len], dest, &rights[..rights_count])
            .map(|sent| sent as i64)
    })
}

fn handle_recvmsg(raw_fd: u64, user_msghdr: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match socket_index(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if user_msghdr == 0 {
        return Ok(Err(Errno::EFAULT));
    }
    let mut hdr = [0u8; 56];
    if let Err(e) = copy_from_user(&mut hdr, user_msghdr) {
        return Ok(Err(e));
    }
    let msg_iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let msg_iovlen = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let msg_control = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let msg_controllen = u64::from_le_bytes(hdr[40..48].try_into().unwrap()) as usize;

    if msg_iovlen == 0 {
        return Ok(Ok(0));
    }
    let mut iov0 = [0u8; 16];
    if let Err(e) = copy_from_user(&mut iov0, msg_iov) {
        return Ok(Err(e));
    }
    let iov_base = u64::from_le_bytes(iov0[0..8].try_into().unwrap());
    let iov_len = (u64::from_le_bytes(iov0[8..16].try_into().unwrap()) as usize).min(SOCK_BUF_CAP);

    let mut buf = [0u8; SOCK_BUF_CAP];
    let recv_res = with_net_state(|table| table.recv(idx, &mut buf[..iov_len]))?;
    let (n, _peer, rights, rights_count) = match recv_res {
        Ok(t) => t,
        Err(e) => return Ok(Err(e)),
    };
    if n > 0 {
        if let Err(e) = copy_to_user(iov_base, &buf[..n]) {
            return Ok(Err(e));
        }
    }
    if rights_count > 0 && msg_control != 0 && msg_controllen >= 16 + rights_count * 4 {
        let cmsg_len = 16 + rights_count * 4;
        let mut cmsg = [0u8; 16 + MAX_SCM_RIGHTS_FDS * 4];
        cmsg[0..8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
        cmsg[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_le_bytes());
        cmsg[12..16].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
        for (i, &fd) in rights.iter().enumerate().take(rights_count) {
            let off = 16 + i * 4;
            cmsg[off..off + 4].copy_from_slice(&fd.to_le_bytes());
        }
        if let Err(e) = copy_to_user(msg_control, &cmsg[..cmsg_len]) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(n as i64))
}

fn read_user_sockaddr(user_addr: u64, addrlen: u64) -> Result<SockAddr, Errno> {
    if user_addr == 0 {
        return Err(Errno::EFAULT);
    }
    let len = usize::try_from(addrlen).map_err(|_| Errno::EINVAL)?;
    if !(2..=MAX_SOCKADDR_BYTES).contains(&len) {
        return Err(Errno::EINVAL);
    }
    let mut raw = [0u8; MAX_SOCKADDR_BYTES];
    copy_from_user(&mut raw[..len], user_addr)?;
    SockAddr::parse(&raw[..len])
}

fn write_user_sockaddr(user_addr: u64, user_addrlen: u64, addr: &SockAddr) -> Result<(), Errno> {
    if user_addr == 0 || user_addrlen == 0 {
        return Err(Errno::EFAULT);
    }
    let mut len_bytes = [0u8; 4];
    copy_from_user(&mut len_bytes, user_addrlen)?;
    let max_len = (u32::from_le_bytes(len_bytes) as usize).min(MAX_SOCKADDR_BYTES);
    let mut encoded = [0u8; MAX_SOCKADDR_BYTES];
    let actual_len = addr.encode(&mut encoded);
    let copy_len = max_len.min(actual_len);
    if copy_len > 0 {
        copy_to_user(user_addr, &encoded[..copy_len])?;
    }
    copy_to_user(user_addrlen, &(actual_len as u32).to_le_bytes())
}

fn copy_from_user(dst: &mut [u8], user_src: u64) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(|err| match err {
        UsercopyError::NullPointer
        | UsercopyError::AddressOverflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::PageFault => Errno::EFAULT,
        UsercopyError::LengthExceedsMaximum | UsercopyError::PrivilegeAccessNotDisabled => {
            Errno::EINVAL
        }
    })
}

fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(|err| match err {
        UsercopyError::NullPointer
        | UsercopyError::AddressOverflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::PageFault => Errno::EFAULT,
        UsercopyError::LengthExceedsMaximum | UsercopyError::PrivilegeAccessNotDisabled => {
            Errno::EINVAL
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_fd_window_is_disjoint_from_earlier_subsystems() {
        assert!(!is_socket_fd(0));
        assert!(!is_socket_fd(64));
        assert!(!is_socket_fd(96));
        assert!(is_socket_fd(SOCK_FD_BASE as u64));
        assert!(is_socket_fd((SOCK_FD_BASE + 15) as u64));
        assert!(!is_socket_fd((SOCK_FD_BASE + 16) as u64));
    }
}
