% --- state ---

:- dynamic user/2.          % name, operative
:- dynamic role/2.          % name, operative
:- dynamic file/3.          % filename, threshold, operative
:- dynamic userRole/2.      % user, role
:- dynamic perm/3.          % role, operation, file


% --- imports ---

:- ensure_loaded("utils.pro").
:- ensure_loaded("cac.pro").
:- ensure_loaded("centralized.pro").
:- ensure_loaded("securitymodel.pro").
:- ensure_loaded("operations.pro").
:- ensure_loaded("consistency.pro").


% --- state-change rules ---

:- dynamic rotateKey/1.


% utils


assertPredicate(PRED, ENTITY) :-
    FACT =.. [PRED, ENTITY],
    FACT.

assertPredicate(PRED, ENTITY) :-
    FACT =.. [PRED, ENTITY],
    assert(FACT).


retractPredicate(PRED, ENTITY) :-
    FACT =.. [PRED, ENTITY],
    \+ FACT.

retractPredicate(PRED, ENTITY) :-
    FACT =.. [PRED, ENTITY],
    retractall(FACT).


retractallPredicates(ENTITY) :- 
    foreach(
        predicate(PRED),
        (
            FACT =.. [PRED, ENTITY],
            retractall(FACT);
            true
        )
    ).


% real

init :-
    assert(user(admin, true)),
    assert(role(admin, true)),
    assert(userRole(admin, admin)),

    addUserT(admin),
    addRoleT(admin),
    assignUserToRoleT(admin, admin), 

    initAdmC,
    verifyConsistency.


addUser(USER, []) :-
    \+ user(USER, _),
    assert(user(USER, true)),
    addUserT(USER),
    addUserC(USER),
    updateUnderlying.

addUser(USER, [PR|PRs]) :-
    \+ user(USER, _),
    assertPredicate(PR, USER),
    addUser(USER, PRs).


deleteUser(USER) :-
    user(USER, true),

    % revoke all roles
    foreach(
        (
            role(ROLE, true),
            userRole(USER, ROLE)
        ),
        (
            revokeUserFromRoleC(USER, ROLE) ->
            (
                isRoleKeyRotationNeededOnRUR(USER, ROLE) ->
                    rotateRoleKeyUserRoleC(ROLE);
                true
            );
            true
        )
    ),

    % delete
    deleteUserT(USER),
    deleteUserC(USER),

    % reencrypt
    foreach(
        (
            file(FILE, _, true), operation(OP), 
            canDo(USER, OP, FILE), isEncryptionNeeded(FILE)
        ),
        (
            (role(ROLE, true), userRole(USER, ROLE), isReencryptionNeededOnRUR(USER, ROLE, OP, FILE) ->
                prepareReencryptionC(FILE); true),
            (role(ROLE, true), userRole(USER, ROLE), isEagerReencNeededOnRUR(USER, ROLE, OP, FILE) ->
                reencryptResourceC(FILE); true)
        )
    ),

    % rotate role key
    foreach(
        (
            role(ROLE, true),
            userRole(USER, ROLE)
        ),
        (
            isRoleKeyRotationNeededOnRUR(USER, ROLE) ->
                rotateRoleKeyPermissionsC(ROLE);
            true
        )
    ),

    retractall(userRole(USER, _)),
    retractallPredicates(USER),
    retractall(user(USER, _)),
    assert(user(USER, false)),

    updateUnderlying.


addRole(ROLE, []) :-
    \+ role(ROLE, _),

    assert(role(ROLE, true)),
    assert(userRole(admin, ROLE)),

    addRoleT(ROLE),
    addRoleC(ROLE),
    assignUserToRoleT(admin, ROLE),

    updateUnderlying.

addRole(ROLE, [PR|PRs]) :-
    \+ role(ROLE, _),

    assertPredicate(PR, ROLE),
    addRole(ROLE, PRs).


deleteRole(ROLE) :-
    role(ROLE, true),

    % revoke permissions
    foreach(
        (
            file(FILE, _, true), operation(OP), 
            perm(ROLE, OP, FILE), isEncryptionNeeded(FILE)
        ),
        revokePermissionFromRoleC(ROLE, [OP], FILE)
    ),

    % reencrypt files
    foreach(
        file(FILE, _, true),
        (
            operation(OP), 
            perm(ROLE, OP, FILE), 
            isEncryptionNeeded(FILE),
            isReencryptionNeededOnRP(ROLE, OP, FILE),
            prepareReencryptionC(FILE);
            true
        )
    ),
    foreach(
        file(FILE, _, true),
        (
            operation(OP), 
            perm(ROLE, OP, FILE), 
            isEncryptionNeeded(FILE),
            isEagerReencNeededOnRP(ROLE, OP, FILE),
            reencryptResourceC(FILE);
            true
        )
    ),

    % revoke users
    foreach(
        (
            userRole(USER, ROLE),
            user(USER, true)
        ),
        revokeUserFromRoleC(USER, ROLE)
    ),

    deleteRoleT(ROLE),
    deleteRoleC(ROLE),

    retractall(userRole(_, ROLE)),
    retractall(perm(ROLE, _, _)),
    retractallPredicates(ROLE),
    retractall(role(ROLE, _)),
    assert(role(ROLE, false)),

    updateUnderlying.


addResource(USER, FILE, [], THRESHOLD) :-
    \+ file(FILE, _, _),

    assert(file(FILE, THRESHOLD, true)),
    foreach(
        operation(OP),
        assert(perm(admin, OP, FILE))
    ),

    (isEncryptionNeeded(FILE) -> (
        addResourceC(FILE),
        writeResourceC(USER, FILE)
    ); true),

    addResourceT(FILE),
    foreach(
        operation(OP),
        assignPermissionToRoleT(admin, [OP], FILE)
    ),

    updateUnderlying.

addResource(USER, FILE, [PR|PRs], THRESHOLD) :-
    \+ file(FILE, _, _),

    assertPredicate(PR, FILE),
    addResource(USER, FILE, PRs, THRESHOLD).


deleteResource(FILE) :-
    file(FILE, _, true),

    deleteResourceT(FILE),
    
    (isEncryptionNeeded(FILE) ->(
        foreach(
            role(ROLE, true),
            (
                operation(OP),
                perm(ROLE, OP, FILE),
                revokePermissionFromRoleC(ROLE, [OP], FILE);
                true
            )
        ),
        deleteResourceC(FILE)
    ); true),

    retractall(file(FILE, _, _)),
    assert(file(FILE, 0, false)),
    retractall(perm(_, _, FILE)),
    retractallPredicates(FILE),

    updateUnderlying.


assignUserToRole(USER, ROLE) :- user(USER, true), role(ROLE, true), userRole(USER, ROLE).
assignUserToRole(USER, ROLE) :-
    user(USER, true), role(ROLE, true),

    assert(userRole(USER, ROLE)),

    assignUserToRoleT(USER, ROLE),
    assignUserToRoleC(USER, ROLE),

    updateUnderlying.


revokeUserFromRole(USER, ROLE) :- user(USER, true), role(ROLE, true), \+ userRole(USER, ROLE).
revokeUserFromRole(USER, ROLE) :-
    user(USER, true), role(ROLE, true),

    revokeUserFromRoleT(USER, ROLE),
    revokeUserFromRoleC(USER, ROLE),

    % rotate role key
    (isRoleKeyRotationNeededOnRUR(USER, ROLE) ->
        rotateRoleKeyUserRoleC(ROLE); true),

    % file reencryption
    foreach(
        file(FILE, _, true),
        (
            operation(OP),
            perm(ROLE, OP, FILE), 
            isEncryptionNeeded(FILE),
            isReencryptionNeededOnRUR(USER, ROLE, OP, FILE),
            prepareReencryptionC(FILE);
            true
        )
    ),
    foreach(
        file(FILE, _, true),
        (
            operation(OP),
            perm(ROLE, OP, FILE), 
            isEncryptionNeeded(FILE),
            isEagerReencNeededOnRUR(USER, ROLE, OP, FILE),
            reencryptResourceC(FILE);
            true
        )
    ),

    % rotate role key
    (isRoleKeyRotationNeededOnRUR(USER, ROLE) ->
        rotateRoleKeyPermissionsC(ROLE); true),

    retractall(userRole(USER, ROLE)).


assignPermissionToRole(_, [], _).

assignPermissionToRole(ROLE, [OP|OPs], FILE) :-
    role(ROLE, true), file(FILE, _, true),

    perm(ROLE, OP, FILE),
    assignPermissionToRole(ROLE, OPs, FILE).

assignPermissionToRole(ROLE, [OP|OPs], FILE) :-
    \+ perm(ROLE, OP, FILE),

    assert(perm(ROLE, OP, FILE)),

    assignPermissionToRoleT(ROLE, [OP], FILE),
    (isEncryptionNeeded(FILE) ->
        assignPermissionToRoleC(ROLE, [OP], FILE); true),

    updateUnderlying,

    assignPermissionToRole(ROLE, OPs, FILE).


revokePermissionFromRoleInt(_, [], FILE, REENC, EAG_REENC) :-
    (
        (
            isEncryptionNeeded(FILE),
            REENC == true
        ) ->
        prepareReencryptionC(FILE); true
    ),
    (
        (
            isEncryptionNeeded(FILE),
            EAG_REENC == true
        ) ->
        reencryptResourceC(FILE); true
    ),

    updateUnderlying.

revokePermissionFromRoleInt(ROLE, [OP|OPs], FILE, REENC, EAG_REENC) :-
    revokePermissionFromRoleT(ROLE, [OP], FILE),

    (isEncryptionNeeded(FILE) -> 
        revokePermissionFromRoleC(ROLE, [OP], FILE); true),

    retractall(perm(ROLE, OP, FILE)),

    (isReencryptionNeededOnRP(ROLE, OP, FILE) -> REENC = true; true),
    (isEagerReencNeededOnRP(ROLE, OP, FILE) -> EAG_REENC = true; true),

    revokePermissionFromRoleInt(ROLE, OPs, FILE, REENC, EAG_REENC).

revokePermissionFromRole(ROLE, OPs, FILE) :-
    role(ROLE, true), file(FILE, _, true),
    revokePermissionFromRoleInt(ROLE, OPs, FILE, _, _).


assignPredicate(PRED, ENTITY) :-
    assertPredicate(PRED, ENTITY),
    updateUnderlying.

revokePredicate(PRED, ENTITY) :-
    retractPredicate(PRED, ENTITY),
    updateUnderlying.


readResource(USER, FILE) :-
    canDoT(USER, read, FILE),
    readResourceC(USER, FILE).


writeResource(USER, FILE) :-
    canDoT(USER, write, FILE),
    writeResourceC(USER, FILE).


setThreshold(FILE, THRESHOLD) :-
    retractall(file(FILE, _, true)),
    assert(file(FILE, THRESHOLD, true)).
    % TODO: append


updateUnderlying :- 
    % file that need encryption
    foreach(
        (
            file(FILE, _, _),
            isEncryptionNeeded(FILE), 
            \+ isProtectedWithCAC(FILE)
        ),
        (
            addResourceC(FILE),
            foreach(
                perm(ROLE, OP, FILE),
                assignPermissionToRoleC(ROLE, [OP], FILE)
            )
        )
    ),

    % file that no longer need encryption
    foreach(
        (
            file(FILE, _, _),
            \+ isEncryptionNeeded(FILE),
            isProtectedWithCAC(FILE)
        ),
        (
            foreach(
                perm(ROLE, OP, FILE),
                revokePermissionFromRoleC(ROLE, [OP], FILE)
            ),
            deleteResourceC(FILE)
        )
    ),
    
    % role key rotation
    foreach(
        (
            user(USER, _),
            role(ROLE, _)
        ),
        (
            isRoleKeyRotationNeededOnRUR(USER, ROLE),
            \+ canUserBeC(USER, ROLE),
            canUserBeCacheC(USER, ROLE),
            assert(rotateKey(ROLE)),
            rotateRoleKeyUserRoleC(ROLE);
            true
        )
    ),

    % reencryption on revoke user role
    foreach(
        (
            user(USER, _),
            file(FILE, _, _)
        ),
        (
            role(ROLE, _),
            isReencryptionNeededOnRUR(USER, ROLE, OP, FILE),
            isEncryptionNeeded(FILE),
            operation(OP),
            \+ canUserDoC(USER, OP, FILE),
            canUserDoViaRoleCacheLastC(USER, ROLE, OP, FILE),
            prepareReencryptionC(FILE);
            true
        )
    ),

    % eager reencryption on revoke user role
    foreach(
        (
            user(USER, _),
            file(FILE, _, _)
        ),
        (
            role(ROLE, _),
            isEagerReencNeededOnRUR(USER, ROLE, OP, FILE),
            isEncryptionNeeded(FILE),
            operation(OP),
            \+ canUserDoC(USER, OP, FILE),
            canUserDoViaRoleCacheC(USER, ROLE, OP, FILE),
            reencryptResourceC(FILE);
            true
        )
    ),

    % reencryption on revoke permission
    foreach(
        (
            role(ROLE, _),
            file(FILE, _, _)
        ),
        (
            operation(OP),
            isReencryptionNeededOnRP(ROLE, OP, FILE),
            isEncryptionNeeded(FILE),
            \+ canRoleDoC(ROLE, OP, FILE),
            canRoleDoCacheLastC(ROLE, OP, FILE),
            prepareReencryptionC(FILE);
            true
        )
    ),

    % eager reencryption on revoke permission
    foreach(
        (
            role(ROLE, _),
            file(FILE, _, _)
        ),
        (
            operation(OP),
            isEagerReencNeededOnRP(ROLE, OP, FILE),
            isEncryptionNeeded(FILE),
            \+ canRoleDoC(ROLE, OP, FILE),
            canRoleDoCacheC(ROLE, OP, FILE),
            reencryptResourceC(FILE);
            true
        )
    ),

    % rotate role key (2)
    foreach(
        rotateKey(ROLE),
        rotateRoleKeyPermissionsC(ROLE)
    ),
    retractall(rotateKey(ROLE)),

    % verify canDo consistency
    verifyConsistency.


% --- queries ---

canDo(USER, OP, FILE) :-
    user(USER, true), role(ROLE, true), userRole(USER, ROLE),
    perm(ROLE, OP, FILE), file(FILE, _, true).


% --- debug ---

% :- init.
% :- addUser(simone, []), initUserC(simone).
% :- addUser(alessandro, [colludingProne]), initUserC(alessandro).

% :- addRole(staff, []),
%     assignUserToRole(simone, staff),
%     assignUserToRole(alessandro, staff).

% :- addResource(admin, bilancio, [], 10).
% :- addResource(admin, presenze, [enc], 10).
% :- addResource(admin, stipendi, [enc, cspNoEnforce], 10).
% :- addResource(admin, navicella, [enc, eager, cspNoEnforce], 10).
% :- assignPermissionToRole(staff, [read, write], bilancio).
% :- assignPermissionToRole(staff, [read, write], presenze).
% :- assignPermissionToRole(staff, [read, write], stipendi).
% :- assignPermissionToRole(staff, [read, write], navicella).

