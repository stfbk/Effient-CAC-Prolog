% dynamic info

status(inc).
status(ope).
status(cache).
status(del).

:- dynamic userC/2.             % user, status
:- dynamic roleC/3.             % role, role_version, status
:- dynamic fileC/5.             % file, file_version, key_file_version, status, contain_file
:- dynamic userRoleC/4.         % user, role, role_version, status
:- dynamic permC/6.             % role, file, role_version, file_version, operation, status


% imoprts

% :- ensure_loaded("extended.pro").
:- ensure_loaded("utils.pro").
:- ensure_loaded("operations.pro").


% --- utils ---

% cacTuple(_, _, _, _) :- true.
cacTuple(OP, TYPE, TEXT, CONTENT_OLD) :-
    convertArray(CONTENT_OLD, CONTENT),
    atom_concat("[CRYPTO] ", OP, P1),
    atom_concat(P1, "⟨", P2),
    atom_concat(P2, TYPE, P3),
    atom_concat(P3, ", ", P4),
    atom_concat(P4, TEXT, P5),
    atom_concat(P5, "⟩~n", P6),
    ansi_format([fg(magenta)], P6, CONTENT).

printUserC(OP, CONTENT) :-          cacTuple(OP, "U", "~a, ~a", CONTENT).
printRoleC(OP, CONTENT) :-          cacTuple(OP, "R", "~a, ~a, ~a", CONTENT).
printFileC(OP, CONTENT) :-          cacTuple(OP, "F", "~a, ~a, ~a, ~a, ~a", CONTENT).
printUserRoleC(OP, CONTENT) :-      cacTuple(OP, "UR", "~a, ~a, ~a, ~a", CONTENT).
printPermC(OP, CONTENT) :-          cacTuple(OP, "PA", "~a, ~a, ~a, ~a, ~a, ~a", CONTENT).


nextVersion(VERSION, NEXT_VERSION) :- sum_list([VERSION, 1], NEXT_VERSION).


printTuples :-
    foreach(
        status(STATUS),
        (
            ansi_format([fg(magenta)], "--- ~a ---~n", [STATUS]),

            % users
            ansi_format([fg(magenta)], "- userC~n", []),
            foreach(
                userC(USER, STATUS),
                printUserC("  ", [USER, STATUS])
            ),

            % userrole
            ansi_format([fg(magenta)], "- userRoleC~n", []),
            foreach(
                userRoleC(USER, ROLE, ROLE_V, STATUS),
                printUserRoleC("  ", [USER, ROLE, ROLE_V, STATUS])
            ),

            % roles
            ansi_format([fg(magenta)], "- roleC~n", []),
            foreach(
                roleC(ROLE, ROLE_V, STATUS),
                printRoleC("  ", [ROLE, ROLE_V, STATUS])
            ),

            % permissions
            ansi_format([fg(magenta)], "- permC~n", []),
            foreach(
                permC(ROLE, FILE, ROLE_V, FILE_V, OP, STATUS),
                printPermC("  ", [ROLE, FILE, ROLE_V, FILE_V, OP, STATUS])
            ),

            % files
            ansi_format([fg(magenta)], "- fileC~n", []),
            foreach(
                fileC(FILE, FILE_V, KEY_FILE_V, STATUS, CONTAIN_FILE),
                printFileC("  ", [FILE, FILE_V, KEY_FILE_V, STATUS, CONTAIN_FILE])
            )
        )
    ).


% --- state-change rules ---

initAdmC :-
    % create user tuple
    assert(userC(admin, ope)),
    printUserC("+", [admin, ope]),

    % create role tuple
    assert(roleC(admin, 1, ope)),
    printRoleC("+", [admin, 1, ope]),

    % assign admin to role admin
    assert(userRoleC(admin, admin, 1, ope)),
    printUserRoleC("+", [admin, admin, 1, ope]).


initUserC(USER) :-
    userC(USER, inc),
    
    % delete old tuple
    retractall(userC(USER, inc)),
    printUserC("-", [USER, inc]),

    % create new tuple
    assert(userC(USER, ope)),
    printUserC("+", [USER, ope]).
    

addUserC(USER) :-
    % checks
    \+ userC(USER, _),

    % create tuple
    assert(userC(USER, inc)),
    printUserC("+", [USER, inc]).


deleteUserC(USER) :-
    % checks
    (userC(USER, ope); userC(USER, inc)), \+ userRoleC(USER, _, _, ope),

    % delete tuple
    retractall(userC(USER, ope)),
    printUserC("-", [USER, ope]),

    % create new tuple
    assert(userC(USER, cache)),
    printUserC("+", [USER, cache]).

% deleteUserC(USER) :-
%     % checks
%     userC(USER, inc), \+ userRoleC(USER, _, _, ope),

%     % delete tuple
%     retractall(userC(USER, inc)),
%     printUserC("-", [USER, inc]),

%     % create new tuple
%     assert(userC(USER, cache)),
%     printUserC("+", [USER, cache]).


addRoleC(ROLE) :-
    % checks
    \+ roleC(ROLE, _, _),

    % create tuple
    assert(roleC(ROLE, 1, ope)),
    printRoleC("+", [ROLE, 1, ope]),

    % assign admin to role
    assert(userRoleC(admin, ROLE, 1, ope)),
    printUserRoleC("+", [admin, ROLE, 1, ope]).


deleteRoleC(ROLE) :-
    % checks
    roleC(ROLE, ROLE_V, ope), 
    \+ userRoleC(_, ROLE, _, ope), 
    \+ permC(ROLE, _, _, _, _, ope),

    % replace tuple
    retractall(roleC(ROLE, ROLE_V, ope)),
    printRoleC("-", [ROLE, ROLE_V, ope]),
    assert(roleC(ROLE, ROLE_V, cache)),
    printRoleC("+", [ROLE, ROLE_V, cache]).


addResourceC(FILE) :-
    % checks
    \+ fileC(FILE, _, _, ope, _),
    
    % create tuple
    assert(fileC(FILE, 1, 1, ope, false)),
    printFileC("+", [FILE, 1, 1, ope, false]),

    % assign permission to role admin
    allOperations(OPS),
    assignPermissionToRoleC(admin, OPS, FILE).


deleteResourceC(FILE) :-
    % checks
    fileC(FILE, FILE_V, KEY_V, ope, _), 
    \+ permC(_, FILE, _, _, _, ope),

    % replace tuple
    retractall(fileC(FILE, FILE_V, KEY_V, ope, _)), 
    printFileC("-", [FILE, FILE_V, KEY_V, ope, "*"]),
    assert(fileC(FILE, FILE_V, KEY_V, del, false)),
    printFileC("+", [FILE, FILE_V, KEY_V, del, false]),

    % cleanup
    cleanupC.


assignUserToRoleC(USER, ROLE) :-
    % checks
    userC(USER, ope),
    roleC(ROLE, ROLE_V, ope),

    % create tuple
    assert(userRoleC(USER, ROLE, ROLE_V, ope)),
    printUserRoleC("+", [USER, ROLE, ROLE_V, ope]).


revokeUserFromRoleC(USER, ROLE) :-
    % checks
    userRoleC(USER, ROLE, ROLE_V, ope),

    % move tuple
    retractall(userRoleC(USER, ROLE, ROLE_V, ope)),
    printUserRoleC("-", [USER, ROLE, ROLE_V, ope]),
    assert(userRoleC(USER, ROLE, ROLE_V, cache)),
    printUserRoleC("+", [USER, ROLE, ROLE_V, cache]).


assignPermissionToRoleC(_, [], _).

assignPermissionToRoleC(ROLE, [OP|OPs], FILE) :-
    % checks
    roleC(ROLE, ROLE_V, ope),
    fileC(FILE, FILE_V, FILE_V, ope, _),
    permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope),

    % other permissions
    assignPermissionToRoleC(ROLE, OPs, FILE).

assignPermissionToRoleC(ROLE, [OP|OPs], FILE) :-
    % checks
    roleC(ROLE, ROLE_V, ope),
    fileC(FILE, FILE_V, FILE_V, ope, _),
    \+ permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope),

    % add tuple
    assert(permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope)),
    printPermC("+", [ROLE, FILE, ROLE_V, FILE_V, OP, ope]),
    
    % other permissions
    assignPermissionToRoleC(ROLE, OPs, FILE).


revokePermissionFromRoleC(_, [], _).

revokePermissionFromRoleC(ROLE, [OP|OPs], FILE) :-
    % checks
    roleC(ROLE, ROLE_V, ope),
    fileC(FILE, FILE_V, FILE_V, ope, _),
    \+ permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope),

    % other permissions
    revokePermissionFromRoleC(ROLE, OPs, FILE).

revokePermissionFromRoleC(ROLE, [OP|OPs], FILE) :-
    % checks
    roleC(ROLE, ROLE_V, ope),
    fileC(FILE, FILE_V, FILE_V, ope, _),
    permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope),

    % move tuple
    retractall(permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope)),
    printPermC("-", [ROLE, FILE, ROLE_V, FILE_V, OP, ope]),
    assert(permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache)),
    printPermC("+", [ROLE, FILE, ROLE_V, FILE_V, OP, cache]),

    % other permissions
    revokePermissionFromRoleC(ROLE, OPs, FILE).


prepareReencryptionC(FILE) :-
    % checks
    fileC(FILE, FILE_V_LAST, FILE_V_LAST, ope, _),
    nextVersion(FILE_V_LAST, FILE_V_LAST_NEXT),

    % replace old tuples
    foreach(
        fileC(FILE, FILE_V, KEY_FILE_V, ope, CONTAIN_FILE),
        (
            retractall(fileC(FILE, FILE_V, KEY_FILE_V, ope, CONTAIN_FILE)),
            printFileC("-", [FILE, FILE_V, KEY_FILE_V, ope, CONTAIN_FILE]),
            assert(fileC(FILE, FILE_V, FILE_V_LAST_NEXT, ope, CONTAIN_FILE)),
            printFileC("+", [FILE, FILE_V, FILE_V_LAST_NEXT, ope, CONTAIN_FILE])
        )
    ),

    % add new tuple
    assert(fileC(FILE, FILE_V_LAST_NEXT, FILE_V_LAST_NEXT, ope, false)),
    printFileC("+", [FILE, FILE_V_LAST_NEXT, FILE_V_LAST_NEXT, ope, false]),

    % replace perms
    foreach(
        permC(USER, FILE, ROLE_V, FILE_V_LAST, OP, ope),
        (
            retractall(permC(USER, FILE, ROLE_V, FILE_V_LAST, OP, ope)),
            printPermC("-", [USER, FILE, ROLE_V, FILE_V_LAST, OP, ope]),
            assert(permC(USER, FILE, ROLE_V, FILE_V_LAST, OP, cache)),
            printPermC("+", [USER, FILE, ROLE_V, FILE_V_LAST, OP, cache]),
            assert(permC(USER, FILE, ROLE_V, FILE_V_LAST_NEXT, OP, ope)),
            printPermC("+", [USER, FILE, ROLE_V, FILE_V_LAST_NEXT, OP, ope])
        )
    ),

    % move unused tuple
    (
        fileC(FILE, FILE_V_LAST, KEY_FILE_V, ope, false),
        retractall(fileC(FILE, FILE_V_LAST, KEY_FILE_V, ope, false)),
        printFileC("-", [FILE, FILE_V_LAST, KEY_FILE_V, ope, false]),
        assert(fileC(FILE, FILE_V_LAST, KEY_FILE_V, del, false)),
        printFileC("+", [FILE, FILE_V_LAST, KEY_FILE_V, del, false]);
        true
    ).


reencryptResourceC(FILE) :-
    readResourceC(admin, FILE),
    writeResourceC(admin, FILE).


rotateRoleKeyUserRoleC(ROLE) :-
    % checks
    roleC(ROLE, ROLE_V, ope),

    % replace role tuple
    nextVersion(ROLE_V, ROLE_V_NEXT),
    assert(roleC(ROLE, ROLE_V_NEXT, ope)),
    printRoleC("+", [ROLE, ROLE_V_NEXT, ope]),

    % replace userrole tuples
    foreach(
        userRoleC(USER, ROLE, ROLE_V, ope),
        (
            assert(userRoleC(USER, ROLE, ROLE_V_NEXT, ope)),
            printUserRoleC("+", [USER, ROLE, ROLE_V_NEXT, ope])
        )
    ).


rotateRoleKeyPermissionsC(ROLE) :-
    % checks
    roleC(ROLE, ROLE_V, ope),
    roleC(ROLE, ROLE_V_NEXT, ope),
    ROLE_V < ROLE_V_NEXT,

    % replace permissions tuple
    foreach(
        permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope),
        (
            retractall(permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope)),
            printPermC("-", [ROLE, FILE, ROLE_V, FILE_V, OP, ope]),
            assert(permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache)),
            printPermC("+", [ROLE, FILE, ROLE_V, FILE_V, OP, cache]),
            assert(permC(ROLE, FILE, ROLE_V_NEXT, FILE_V, OP, ope)),
            printPermC("+", [ROLE, FILE, ROLE_V_NEXT, FILE_V, OP, ope])
        )
    ),

    % delete old user role tueples
    foreach(
        userRoleC(USER, ROLE, ROLE_V, ope),
        (
            retractall(userRoleC(USER, ROLE, ROLE_V, ope)),
            printUserRoleC("-", [USER, ROLE, ROLE_V, ope]),
            assert(userRoleC(USER, ROLE, ROLE_V, cache)),
            printUserRoleC("+", [USER, ROLE, ROLE_V, cache])
        )
    ),

    % delete old role tuple
    retractall(roleC(ROLE, ROLE_V, ope)),
    printRoleC("-", [ROLE, ROLE_V, ope]),
    assert(roleC(ROLE, ROLE_V, cache)),
    printRoleC("+", [ROLE, ROLE_V, cache]).
    

readResourceC(USER, FILE) :-
    % checks
    userC(USER, ope),
    userRoleC(USER, ROLE, ROLE_V, ope),
    roleC(ROLE, ROLE_V, ope),
    permC(ROLE, FILE, ROLE_V, FILE_V, read, ope),
    fileC(FILE, FILE_V, _, ope, _).


writeResourceC(USER, FILE) :-
    % checks
    userC(USER, ope),
    userRoleC(USER, ROLE, ROLE_V, ope),
    roleC(ROLE, ROLE_V, ope),
    permC(ROLE, FILE, ROLE_V, FILE_V_LAST, write, ope),
    fileC(FILE, FILE_V_LAST, FILE_V_LAST, ope, _),

    % replace tuple
    foreach(
        (
            fileC(FILE, FILE_V, FILE_V_LAST, ope, CONTAIN_FILE), 
            FILE_V \= FILE_V_LAST
        ),
        (
            retractall(fileC(FILE, FILE_V, FILE_V_LAST, ope, CONTAIN_FILE)),
            printFileC("-", [FILE, FILE_V, FILE_V_LAST, ope, CONTAIN_FILE]),
            assert(fileC(FILE, FILE_V, FILE_V_LAST, del, CONTAIN_FILE)),
            printFileC("+", [FILE, FILE_V, FILE_V_LAST, del, CONTAIN_FILE])
        )
    ),

    % update tuple
    (
        fileC(FILE, FILE_V_LAST, FILE_V_LAST, ope, false),
        retractall(fileC(FILE, FILE_V_LAST, FILE_V_LAST, ope, false)),
        printFileC("-", [FILE, FILE_V_LAST, FILE_V_LAST, ope, false]),
        assert(fileC(FILE, FILE_V_LAST, FILE_V_LAST, ope, true)),
        printFileC("+", [FILE, FILE_V_LAST, FILE_V_LAST, ope, true])
    ),

    % cleanup
    cleanupC.


% TODO:
% appendResource()

cleanupC :-
    % permissions
    foreach(
        (
            permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache),
            \+ fileC(FILE, FILE_V, _, ope, _)
        ),
        (
            retractall(permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache)),
            printPermC("-", [ROLE, FILE, ROLE_V, FILE_V, OP, cache]),
            assert(permC(ROLE, FILE, ROLE_V, FILE_V, OP, del)),
            printPermC("+", [ROLE, FILE, ROLE_V, FILE_V, OP, del])
        )
    ),

    % roles
    foreach(
        (
            roleC(ROLE, ROLE_V, cache),
            \+ permC(ROLE, _, ROLE_V, _, _, cache)
        ),
        (
            retractall(roleC(ROLE, ROLE_V, cache)),
            printRoleC("-", [ROLE, ROLE_V, cache]),
            assert(roleC(ROLE, ROLE_V, del)),
            printRoleC("+", [ROLE, ROLE_V, del])
        )
    ),

    % user role
    foreach(
        (
            userRoleC(USER, ROLE, ROLE_V, cache),
            (
                \+ roleC(ROLE, ROLE_V, ope),
                \+ roleC(ROLE, ROLE_V, cache)
            )
        ),
        (
            retractall(userRoleC(USER, ROLE, ROLE_V, cache)),
            printUserRoleC("-", [USER, ROLE, ROLE_V, cache]),
            assert(userRoleC(USER, ROLE, ROLE_V, del)),
            printUserRoleC("+", [USER, ROLE, ROLE_V, del])
        )
    ),

    % users
    foreach(
        (
            userC(USER, cache),
            \+ userRoleC(USER, _, _, cache)
        ),
        (
            retractall(userC(USER, cache)),
            printUserC("-", [USER, cache]),
            assert(userC(USER, del)),
            printUserC("+", [USER, del])
        )
    ).


% --- queries ---

isProtectedWithCAC(FILE) :-
    fileC(FILE, _, _, ope, _).

canUserDoC(USER, OP, FILE) :-
    roleC(ROLE, ROLE_V, ope),
    userRoleC(USER, ROLE, ROLE_V, ope),
    permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope),
    fileC(FILE, FILE_V, _, ope, _).

canUserDoViaRoleCacheC(USER, ROLE, OP, FILE) :-
    (roleC(ROLE, ROLE_V, ope); roleC(ROLE, ROLE_V, cache)),
    (userRoleC(USER, ROLE, ROLE_V, ope); userRoleC(USER, ROLE, ROLE_V, cache)),
    (permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope); permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache)),
    fileC(FILE, FILE_V, _, ope, _).

canUserDoViaRoleCacheLastC(USER, ROLE, OP, FILE) :-
    (roleC(ROLE, ROLE_V, ope); roleC(ROLE, ROLE_V, cache)),
    (userRoleC(USER, ROLE, ROLE_V, ope); userRoleC(USER, ROLE, ROLE_V, cache)),
    (permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope); permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache)),
    fileC(FILE, FILE_V, FILE_V, ope, _).


canRoleDoC(ROLE, OP, FILE) :-
    roleC(ROLE, ROLE_V, ope),
    permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope),
    fileC(FILE, FILE_V, _, ope, _).

canRoleDoCacheC(ROLE, OP, FILE) :-
    (roleC(ROLE, ROLE_V, ope); roleC(ROLE, ROLE_V, cache)),
    (permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope); permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache)),
    fileC(FILE, FILE_V, _, ope, _).

canRoleDoCacheLastC(ROLE, OP, FILE) :-
    (roleC(ROLE, ROLE_V, ope); roleC(ROLE, ROLE_V, cache)),
    (permC(ROLE, FILE, ROLE_V, FILE_V, OP, ope); permC(ROLE, FILE, ROLE_V, FILE_V, OP, cache)),
    fileC(FILE, FILE_V, FILE_V, ope, _).


canUserBeC(USER, ROLE) :-
    roleC(ROLE, ROLE_V, ope),
    userRoleC(USER, ROLE, ROLE_V, ope).

canUserBeCacheC(USER, ROLE) :-
    roleC(ROLE, ROLE_V, ope),
    (userRoleC(USER, ROLE, ROLE_V, ope); userRoleC(USER, ROLE, ROLE_V, cache)).


% --- debug ---

% :- initAdmC.

% :- addUserC(simone).
% :- initUserC(simone).

% :- addRoleC(staff).
% :- assignUserToRoleC(simone, staff).
% :- addResourceC(bilancio).
% :- assignPermissionToRoleC(staff, [read, write], bilancio).
% :- writeResourceC(simone, bilancio).


