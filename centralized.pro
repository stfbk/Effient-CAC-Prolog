% --- state ---

:- dynamic userT/1.         % user name
:- dynamic roleT/1.         % role name
:- dynamic userRoleT/2.     % user, role
:- dynamic fileT/1.         % file name
:- dynamic permT/3.         % role, operation, file

% import

:- ensure_loaded("extended.pro").


% --- utils ---

% rbacPrint(_, _) :- true.
rbacPrint(TEXT, CONTENT_OLD) :-
    convertArray(CONTENT_OLD, CONTENT),
    atom_concat("[TRADIT] ", TEXT, O1),
    atom_concat(O1, "~n", O2),
    ansi_format([fg(cyan)], O2, CONTENT).


% --- state-change rules ---

addUserT(USER) :- userT(USER).
addUserT(USER) :- 
    \+ userT(USER),
    assert(userT(USER)),
    rbacPrint("Create user ~a", [USER]).


addRoleT(ROLE) :- roleT(ROLE).
addRoleT(ROLE) :-
    \+ roleT(ROLE),
    assert(roleT(ROLE)),
    rbacPrint("Create role ~a", [ROLE]).

addResourceT(FILE) :- fileT(FILE).
addResourceT(FILE) :-
    \+ fileT(FILE),
    assert(fileT(FILE)),
    rbacPrint("Create file ~a", [FILE]).

assignUserToRoleT(USER, ROLE) :- userRoleT(USER, ROLE).
assignUserToRoleT(USER, ROLE) :-
    userT(USER), roleT(ROLE),                                   % checks
    \+ userRoleT(USER, ROLE),                                   % already member
    assert(userRoleT(USER, ROLE)),
    rbacPrint("Assign ~a to ~a", [USER, ROLE]).

assignPermissionToRoleT(_, [], _).
assignPermissionToRoleT(ROLE, [OP|OPs], FILE) :-
    roleT(ROLE), fileT(FILE), operation(OP),

    assert(permT(ROLE, OP, FILE)),
    rbacPrint("Assign permission ~a for file ~a to role ~a", [OP, FILE, ROLE]),

    assignPermissionToRoleT(ROLE, OPs, FILE).

revokePermissionFromRoleT(_, [], _).
revokePermissionFromRoleT(ROLE, [OP|OPs], FILE) :-
    roleT(ROLE), fileT(FILE), operation(OP),

    retractall(permT(ROLE, OP, FILE)),
    rbacPrint("Assign permission ~a for file ~a to role ~a", [OP, FILE, ROLE]),

    revokePermissionFromRoleT(ROLE, OPs, FILE).

revokeUserFromRoleT(USER, ROLE) :- \+ userRoleT(USER, ROLE).
revokeUserFromRoleT(USER, ROLE) :-
    userT(USER), roleT(ROLE),
    userRoleT(USER, ROLE),
    retractall(userRoleT(USER, ROLE)),
    rbacPrint("Revoke ~a from ~a", [USER, ROLE]).

deleteResourceT(FILE) :- \+ fileT(FILE).
deleteResourceT(FILE) :-
    fileT(FILE),

    % delete associated permissions
    foreach(
        permT(ROLE, OP, FILE),
        revokePermissionFromRoleT(ROLE, [OP], FILE)
    ),

    % delete allow
    retractall(fileT(FILE)),
    rbacPrint("Delete resource ~a", [FILE]).


deleteRoleT(ROLE) :- \+ roleT(ROLE).
deleteRoleT(ROLE) :-
    roleT(ROLE),

    % delete associated permissions
    foreach(
        permT(ROLE, OP, FILE),
        revokePermissionFromRoleT(ROLE, [OP], FILE)
    ),

    % delete members
    foreach(
        userRoleT(USER, ROLE),
        revokeUserFromRoleT(USER, ROLE)
    ),

    % delete role
    retractall(roleT(ROLE)),
    rbacPrint("Revoke role ~a", [ROLE]).

deleteUserT(USER) :- \+ userT(USER).
deleteUserT(USER) :-
    userT(USER),

    % delete memberships
    foreach(
        userRoleT(USER, ROLE),
        revokeUserFromRoleT(USER, ROLE)
    ),

    retractall(userT(USER)),
    rbacPrint("Delete user ~a", [USER]).


canDoT(USER, OP, FILE) :-
    userT(USER), operation(OP), fileT(FILE),
    roleT(ROLE), userRoleT(USER, ROLE), 
    permT(ROLE, OP, FILE).


% --- queries ---

canDoT(USER, OP, FILE) :-
    % checks
    userT(USER), operation(OP), fileT(FILE),

    % can do
    roleT(ROLE), userRoleT(USER, ROLE), permT(ROLE, OP, FILE).

