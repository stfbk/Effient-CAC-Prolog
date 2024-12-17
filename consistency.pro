% --- import ---

:- ensure_loaded("extended.pro").
:- ensure_loaded("securitymodel.pro").


% --- consistency ---

canDoTC(USER, OP, FILE) :-
    isEncryptionNeeded(FILE), 
    canUserDoC(USER, OP, FILE),
    canDoT(USER, OP, FILE).
canDoTC(USER, OP, FILE) :-
    \+ isEncryptionNeeded(FILE),
    canDoT(USER, OP, FILE).

verifyConsistency :-
    % canDo
    foreach(
        (
            canDo(USER, OP, FILE), 
            \+ canDoTC(USER, OP, FILE)
        ),
        ansi_format([fg(red)], "Access (~a, ~a, ~a) is possibile in extended but not in TC~n", [USER, OP, FILE])
    ),
    foreach(
        (
            canDoTC(USER, OP, FILE), 
            \+ canDo(USER, OP, FILE)
        ),
        ansi_format([fg(red)], "Access (~a, ~a, ~a) is possibile in TC but not in extended~n", [USER, OP, FILE])
    ),

    % queris
    foreach(
        (
            user(USER, _), role(ROLE, _), file(FILE, _, _), operation(OP),
            isReencryptionNeededOnRUR(USER, ROLE, OP, FILE), 
            \+ isEncryptionNeeded(FILE)
        ),
        ansi_format([fg(red)], "When isReencryptionNeededOnRUR(~a, ~a, ~a, ~a) the the file must be isEncryptionNeeded(~a) ~n", 
            [USER, ROLE, OP, FILE, FILE])
    ),
    foreach(
        (
            user(USER, _), role(ROLE, _), file(FILE, _, _), operation(OP),
            isEagerReencNeededOnRUR(USER, ROLE, OP, FILE), 
            \+ isReencryptionNeededOnRUR(USER, ROLE, OP, FILE)
        ),
        ansi_format([fg(red)], "When isEagerReencNeededOnRUR(~a, ~a, ~a, ~a) is true, also isReencryptionNeededOnRUR(~a, ~a, ~a, ~a) must be true ~n", 
            [USER, ROLE, OP, FILE, USER, ROLE, OP, FILE])
    ),
    foreach(
        (
            role(ROLE, _), operation(OP), file(FILE, _, _),
            isReencryptionNeededOnRP(ROLE, OP, FILE), 
            \+ isEncryptionNeeded(FILE)
        ),
        ansi_format([fg(red)], "When isReencryptionNeededOnRP(~a, ~a, ~a) the the file must be isEncryptionNeeded(~a) ~n", [ROLE, OP, FILE, FILE])
    ),
    foreach(
        (
            role(ROLE, _), operation(OP), file(FILE, _, _),
            isEagerReencNeededOnRP(ROLE, OP, FILE), 
            \+ isReencryptionNeededOnRP(ROLE, OP, FILE)
        ),
        ansi_format([fg(red)], "When isEagerReencNeededOnRP(~a, ~a, ~a) is true, also isReencryptionNeededOnRP(~a, ~a, ~a) must be true ~n", [ROLE, OP, FILE, USER, ROLE, FILE])
    ).

