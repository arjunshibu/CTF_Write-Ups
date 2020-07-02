LOLO=blah
echo 224224 | ./crackme0x06
# main() loads an array of environment variables
# check() checks if the sum of password is 16
# parrel() will compare bitwise if the password & 1 == 0: calls dummy()
# in dummy() each loop loads the environment variables and checks if any one contains "LOLO" string
