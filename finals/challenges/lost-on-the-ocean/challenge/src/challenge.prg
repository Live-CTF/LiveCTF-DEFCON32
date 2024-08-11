
PROCEDURE Main()
   LOCAL password

   ? "Welcome!"
   ACCEPT "What is the password? " TO password

   IF validate(password) = 1
      ? "Correct!"
   ELSE
      ? "Incorrect!"
   ENDIF

RETURN

FUNCTION validate(password)
    
    IF SubStr(password, 26, 27) != "p"
      RETURN 0
    ENDIF


    IF SubStr(password, 6, 7) != "_"
      RETURN 0
    ENDIF


    IF SubStr(password, 3, 4) != "a"
      RETURN 0
    ENDIF


    IF SubStr(password, 14, 15) != "H"
      RETURN 0
    ENDIF


    IF SubStr(password, 25, 26) != "p"
      RETURN 0
    ENDIF


    IF SubStr(password, 18, 19) != "0"
      RETURN 0
    ENDIF


    IF SubStr(password, 8, 9) != "0"
      RETURN 0
    ENDIF


    IF SubStr(password, 13, 14) != "_"
      RETURN 0
    ENDIF


    IF SubStr(password, 9, 10) != "x"
      RETURN 0
    ENDIF


    IF SubStr(password, 24, 25) != "1"
      RETURN 0
    ENDIF


    IF SubStr(password, 12, 13) != "o"
      RETURN 0
    ENDIF


    IF SubStr(password, 17, 18) != "B"
      RETURN 0
    ENDIF


    IF SubStr(password, 23, 24) != "l"
      RETURN 0
    ENDIF


    IF SubStr(password, 19, 20) != "u"
      RETURN 0
    ENDIF


    IF SubStr(password, 22, 23) != "C"
      RETURN 0
    ENDIF


    IF SubStr(password, 27, 28) != "3"
      RETURN 0
    ENDIF


    IF SubStr(password, 4, 5) != "s"
      RETURN 0
    ENDIF


    IF SubStr(password, 11, 12) != "r"
      RETURN 0
    ENDIF


    IF SubStr(password, 7, 8) != "F"
      RETURN 0
    ENDIF


    IF SubStr(password, 1, 2) != "x"
      RETURN 0
    ENDIF


    IF SubStr(password, 15, 16) != "a"
      RETURN 0
    ENDIF


    IF SubStr(password, 5, 6) != "e"
      RETURN 0
    ENDIF


    IF SubStr(password, 21, 22) != "_"
      RETURN 0
    ENDIF


    IF SubStr(password, 10, 11) != "P"
      RETURN 0
    ENDIF


    IF SubStr(password, 2, 3) != "B"
      RETURN 0
    ENDIF


    IF SubStr(password, 20, 21) != "r"
      RETURN 0
    ENDIF


    IF SubStr(password, 16, 17) != "r"
      RETURN 0
    ENDIF


    IF SubStr(password, 28, 29) != "r"
      RETURN 0
    ENDIF

RETURN 1

