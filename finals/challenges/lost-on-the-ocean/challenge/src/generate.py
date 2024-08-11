#!/usr/bin/env python3

import random
import hashlib

password = "xBase_F0xPro_HarB0ur_Cl1pp3r"

program_template = """
PROCEDURE Main()
   LOCAL password

   ? "Welcome!"
   //ACCEPT "What is the password? " TO password

   IF HB_ArgC() <= 0
      ? "Usage: ./program <password>"
      RETURN
   ENDIF

   password = HB_ArgV(1)

   IF validate(password) = 1
      ? "Correct!"
   ELSE
      ? "Incorrect!"
   ENDIF

RETURN

FUNCTION validate(password)
    %s
RETURN 1
"""

check_template = """
    IF SubStr(password, %d, %d) != "%s"
      RETURN 0
    ENDIF
"""

password_chars = list(enumerate(password))
random.shuffle(password_chars)
checks = "\n".join(check_template % (i + 1, i + 2, x) for i, x in password_chars)

program_code = program_template % checks

print(program_code)
