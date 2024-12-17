#!/usr/bin/env python3

import random
import string
import sys
import numpy

users = []
userRoles = []
roles = []
permissions = []
files = []
operations = ['read', 'write']
predsAssign = []
preds = ['enc', 'eager', 'cspNoEnforce', 'colludingProne']

def randName(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

def printProlog(txt):
    print(':- format("{}~n", []).'.format(txt))
    print(txt)

def addUser(user=None):
    if user is None:
        user = 'user_' + randName()
    printProlog(':- addUser({}, []).'.format(user))
    printProlog(':- initUserC({}).'.format(user))
    users.append(user)

def deleteUser(user=None):
    if user is None:
        user = random.choice(users)
    printProlog(':- deleteUser({}).'.format(user))
    users.remove(user)

def addRole(role=None):
    if role is None:
        role = 'role_' + randName()
    printProlog(':- addRole({}, []).'.format(role))
    roles.append(role)

def deleteRole(role=None):
    if role is None:
        role = random.choice(roles)
    printProlog(':- deleteRole({}).'.format(role))
    roles.remove(role)

def addResource(user=None, file=None, threshold=None):
    if user is None:
        user = random.choice(users)
    if file is None:
        file = 'file_' + randName()
    if threshold is None:
        threshold = random.randint(1, 10)
    printProlog(':- addResource({}, {}, [], {}).'.format(user, file, threshold))
    files.append(file)

def deleteResource(file=None):
    if file is None:
        file = random.choice(files)
    printProlog(':- deleteResource({}).'.format(file))
    files.remove(file)

def assignUserToRole(user=None, role=None):
    if user is None:
        user = random.choice(users)
    if role is None:
        role = random.choice(roles)
    printProlog(':- assignUserToRole({}, {}).'.format(user, role))
    userRoles.append((user, role))

def revokeUserFromRole(user=None, role=None):
    if user is None and role is None:
        user, role = random.choice(userRoles)
    if user not in users or role not in roles:
        return
    printProlog(':- revokeUserFromRole({}, {}).'.format(user, role))
    userRoles.remove((user, role))

def assignPermissionToRole(role=None, op=None, file=None):
    if role is None:
        role = random.choice(roles)
    if op is None:
        op = []
        for _ in range(random.randint(1, len(operations) - 1)):
            op.append(random.choice(operations))
        # op = random.choice(operations)
    if file is None:
        file = random.choice(files)
    printProlog(':- assignPermissionToRole({}, {}, {}).'.format(role, op, file))
    permissions.append((role, op, file))
    
def revokePermissionFromRole(role=None, op=None, file=None):
    if role is None and op is None and file is None:
        role, op, file = random.choice(permissions)
    if role not in roles or file not in files:
        return
    printProlog(':- revokePermissionFromRole({}, {}, {}).'.format(role, op, file))
    permissions.remove((role, op, file))

def assignPredicate(pred=None, entity=None):
    if pred is None:
        pred = random.choice(preds)
    if entity is None:
        if pred in ['enc', 'eager', 'cspNoEnforce']:
            entity = random.choice(files)
        elif pred == 'colludingProne':
            entity = random.choice(users)
        # entity = random.choice(users + roles + files)
    printProlog(':- assignPredicate({}, {}).'.format(pred, entity))
    predsAssign.append((pred, entity))

def revokePredicate(pred=None, entity=None):
    if pred is None and entity is None:
        pred, entity = random.choice(predsAssign)
    printProlog(':- revokePredicate({}, {}).'.format(pred, entity))
    predsAssign.remove((pred, entity))

def main():
    if len(sys.argv) < 2:
        print("Please, add a parameter")
        return
    
    n = int(sys.argv[1])

    c = numpy.random.choice([addUser, deleteUser, 
                             addRole, deleteRole, 
                             addResource, deleteResource, 
                             assignUserToRole, revokeUserFromRole, 
                             assignPermissionToRole, revokePermissionFromRole,
                             assignPredicate, revokePredicate], n,
                         p=[
                            0.080,   0.040, 
                            0.080,   0.040,
                            0.080,   0.040,
                            0.145,   0.040,
                            0.145,   0.040,
                            0.180,   0.090
                         ])
    for f in c:
        try:
            f()
        except IndexError:
            # skip
            pass

    printProlog(':- verifyConsistency.')
    printProlog(':- printTuples.')
    

if __name__ == '__main__':
    main()
