from z3 import *

s = Solver()
password = []
length = 15
for i in range(length):
  password.append(BitVec('chr{}'.format(i), 8))
  s.add([UGT(password[i], 0x20), ULT(password[i], 0x80)])

code = BitVecVal(0, 16)
code += 0x5417

for i in range(0, length):
  code = code ^ SignExt(8, password[i])
  code = code * 2

s.add(code == 0x8DFA)

if s.check() != unsat:
  model = s.model()
  buf = ""
  for i in range(0, length):
    obj = password[i]
    c = model[obj].as_long()
    buf += chr(c)
  print buf