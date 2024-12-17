% include

:- ensure_loaded("extended.pro").
:- ensure_loaded("consistency.pro").
% :- ensure_loaded("debug_advanced.pro").

:- init.

:- addUser(alice, []), initUserC(alice).
:- addUser(bob, [colludingProne]), initUserC(bob).
:- addUser(david, []), initUserC(david).

:- addRole(staff, []).
:- addRole(engineer, []).

:- assignUserToRole(alice, staff).
:- assignUserToRole(alice, engineer).
:- assignUserToRole(bob, staff).
:- assignUserToRole(bob, engineer).
:- assignUserToRole(david, staff).

:- addResource(admin, budget, [], 1).
:- addResource(admin, shuttle, [enc, cspNoEnforce], 1).
:- addResource(admin, temperature, [enc, eager], 1).

:- assignPermissionToRole(staff, [read], budget).
:- assignPermissionToRole(engineer, [read, write], shuttle).
:- assignPermissionToRole(engineer, [read], temperature).



:- halt.

% debug

% :- init,
%     addUser(simone),
%     initUserK(simone),

%     addRole(staff),
%     addResource(balance),
%     assignUserToRole(simone, staff),
%     assignPermissionToRole(staff, read, balance),
%     assignPredicate(enc, balance),
%     assertConflicts,
%     revokePredicate(enc, balance),
%     assertConflicts.





% :- init.



% :-  init,

%     addUser(simone),
%     initUserK(simone),
%     assignPredicate(colludingProne, simone),

%     addUser(alessandro),
%     initUserK(alessandro),

%     addRole(staff),
%     addRole(engineer),
    
%     addResource(balance),
%     assignPredicate(enc, balance),
%     assignPredicate(cspNoEnforce, balance),

%     addResource(shuttle),
%     assignPredicate(enc, shuttle),

%     assignUserToRole(simone, staff),
%     assignUserToRole(alessandro, staff),
%     assignUserToRole(simone, engineer),

%     assignPermissionToRole(staff, readwrite, balance),
%     assignPermissionToRole(staff, read, shuttle),
%     assignPermissionToRole(engineer, write, shuttle).


% % :- format("initAdmK~n", []).
% % :- initAdmK.

% % :- format("addUser(simone)~n", []).
% % :- addUser(simone).
% % :- initUserK(simone).

% % :- format("addResource(balance)~n", []).
% % :- addResource(balance).

% % :- format("assignPredicate(enc, balance)~n", []).
% % :- assignPredicate(enc, balance).

% % :- format("addRole(staff)~n", []).
% % :- addRole(staff).

% % :- format("assignUserToRole(simone, staff)~n", []).
% % :- assignUserToRole(simone, staff).

% % :- format("assignPermissionToRole(staff, read, balance)~n", []).
% % :- assignPermissionToRole(staff, read, balance).

% % :- assignPredicate(colludingProne, simone).
% % :- assignPredicate(cspNoEnforce, balance).

