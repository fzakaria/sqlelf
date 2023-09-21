import apsw.bestpractice

# forward sqlite logs to logging module
apsw.bestpractice.apply(apsw.bestpractice.recommended)
