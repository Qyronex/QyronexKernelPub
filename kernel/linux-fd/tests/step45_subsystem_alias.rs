// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_fd::{FdTableSet, OpenObjectKind, ReleasedObject, SubsystemHandle};

const H_DEV: SubsystemHandle = SubsystemHandle {
    kind: 1,
    slot: 3,
    generation: 42,
};

const H_NET: SubsystemHandle = SubsystemHandle {
    kind: 3,
    slot: 7,
    generation: 99,
};

#[test]
fn subsystem_alias_open_dup_status_flags_and_last_close_across_fork() {
    let mut set = FdTableSet::<2, 16>::new();
    let parent = set.create_view().unwrap();

    let tok1 = set
        .with_view(parent, |fds| {
            fds.open_subsystem_from(3, H_DEV, false, 0x2).unwrap()
        })
        .unwrap();
    assert_eq!(tok1.fd(), 3);

    set.with_view(parent, |fds| {
        assert_eq!(fds.subsystem_handle(3), Ok(Some(H_DEV)));
        assert_eq!(fds.object_kind(3), Ok(OpenObjectKind::Subsystem(H_DEV)));
        assert_eq!(fds.status_flags(3), Ok(0x2));
        assert_eq!(fds.set_status_flags(3, 0x802), Ok(()));
        assert_eq!(fds.status_flags(3), Ok(0x802));
    })
    .unwrap();

    let dup_tok = set
        .with_view(parent, |fds| fds.duplicate(3, 5, true).unwrap())
        .unwrap();
    assert_eq!(dup_tok.fd(), 5);

    let child = set.fork_view(parent).unwrap();

    let mut released = None;
    let close_in =
        |fds: &mut kernal_linux_fd::FdTable<16>, fd, released: &mut Option<ReleasedObject>| {
            fds.close_with_release(fd, |rel| {
                *released = Some(rel);
                Ok::<(), ()>(())
            })
            .unwrap()
            .unwrap();
        };

    // Closing both descriptors in child must leave parent's shared OFD live without releasing H_DEV.
    set.with_view(child, |fds| close_in(fds, 3, &mut released))
        .unwrap();
    assert_eq!(released, None);
    set.with_view(child, |fds| close_in(fds, 5, &mut released))
        .unwrap();
    assert_eq!(released, None);

    // Closing FD 3 in parent leaves dup'd FD 5 holding the last reference.
    set.with_view(parent, |fds| close_in(fds, 3, &mut released))
        .unwrap();
    assert_eq!(released, None);

    // Closing FD 5 triggers final release of H_DEV exactly once.
    set.with_view(parent, |fds| close_in(fds, 5, &mut released))
        .unwrap();
    assert_eq!(released, Some(ReleasedObject::Subsystem(H_DEV)));
}

#[test]
fn subsystem_bind_exact_replaces_existing_alias_and_cloexec_releases_only_marked() {
    let mut set = FdTableSet::<1, 16>::new();
    let view = set.create_view().unwrap();

    set.with_view(view, |fds| {
        let kept = fds.open_subsystem_from(4, H_DEV, false, 0).unwrap();
        let replaced = fds.open_subsystem_from(8, H_NET, true, 0).unwrap();
        assert_eq!(kept.fd(), 4);
        assert_eq!(replaced.fd(), 8);

        let mut released_prev = None;
        let bound = fds
            .bind_subsystem_exact(8, H_DEV, true, 0x800, |rel| {
                released_prev = Some(rel);
                Ok::<(), ()>(())
            })
            .unwrap()
            .unwrap();
        assert_eq!(bound.fd(), 8);
        assert_eq!(released_prev, Some(ReleasedObject::Subsystem(H_NET)));

        let plan = fds.prepare_close_on_exec().unwrap();
        let closed = fds.commit_close_on_exec(plan).unwrap();
        let mut count = 0;
        for item in closed.into_iter().flatten() {
            assert_eq!(item, ReleasedObject::Subsystem(H_DEV));
            count += 1;
        }
        assert_eq!(count, 1);

        // Kept descriptor (cloexec=false) must still retain H_DEV.
        assert_eq!(fds.subsystem_handle(4), Ok(Some(H_DEV)));
    })
    .unwrap();
}
