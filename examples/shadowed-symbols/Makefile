all: exe

# This library depends libx2.so soname and calls h() from it
y/liby.so: x/libx2.so
	@mkdir -p $(dir $@)
	echo 'extern int foo(); int g() { return foo(); }' | $(CC) -g -o $@ -shared -x c - -Lx -l:libx2.so '-Wl,--no-as-needed,--enable-new-dtags,-rpath,$$ORIGIN/../x'

# This library has both file and soname libx.so
x/libx.so:
	@mkdir -p $(dir $@)
	echo 'int foo(){return 12;}' | $(CC) -g -o $@ -shared -x c -

# This library has both file and soname libx.so
x/libx2.so:
	@mkdir -p $(dir $@)
	echo 'int foo(){return 1000;}' | $(CC) -g -o $@ -shared -x c -

# This links to b/liby.so and c/libx.so, and gets libx.so and liby.so in DT_NEEDED, no paths.
exe: y/liby.so x/libx.so
	echo 'extern int g(); extern int foo(); int main(){ printf("\%d\n", g() + foo()); }' | \
	$(CC) -g -o $@ -include stdio.h -x c - -Ly -Lx -l:liby.so '-Wl,--no-as-needed,--enable-new-dtags,-rpath,$$ORIGIN/y' \
		  -l:libx.so '-Wl,--no-as-needed,--enable-new-dtags,-rpath,$$ORIGIN/x'

clean:
	rm -rf -- x y exe