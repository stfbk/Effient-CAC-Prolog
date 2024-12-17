
convertArray([], []).
convertArray([X|Xs], [Y|Ys]) :-
    is_list(X),
    convertArrayString(X, Y),
    convertArray(Xs, Ys).
convertArray([X|Xs], [X|Ys]) :-
    \+ is_list(X),
    convertArray(Xs, Ys).

convertArrayString([], "<null>").
convertArrayString([X|Xs], RES) :-
    convertArrayStringInt(Xs, P),
    atom_concat(X, P, RES).

convertArrayStringInt([], "").
convertArrayStringInt([X|Xs], RES) :-
    atom_concat(", ", X, P1),
    convertArrayStringInt(Xs, P2),
    atom_concat(P1, P2, RES).
