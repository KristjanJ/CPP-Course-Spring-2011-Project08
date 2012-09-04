# To compile, run 'make' in the same directory as this file

#######################
# Crypto++ location   #
#######################

CRYPTOPPDIR = C:\Users\Kristjan\Desktop\Kristjan\University\C++\cryptopp561

#########################
# Settings for the apps # 
#########################

# Compiler flags for the app
APP_CFLAGS = -Wall -Iinclude -I$(CRYPTOPPDIR)
# Linker flags (order the compiler to link with our library)
LFLAGS = -L$(CRYPTOPPDIR) -lcryptopp 
# The object for the apps
FILESECUREOBJS = obj/main.o
# The names of the apps
FILESECUREAPP = bin/filesecure

# This is the first target. It will be built when you run 'make' or 'make all'
all: $(FILESECUREAPP)
# Rules for linking the test apps
$(FILESECUREAPP): $(FILESECUREOBJS)
	$(CXX) $(FILESECUREOBJS) -o $(FILESECUREAPP) $(LFLAGS)

# Compile each source file of the apps
obj/main.o: src/main.cpp
	$(CXX) $(APP_CFLAGS) -c src/main.cpp -o obj/main.o

clean: 
	rm -rf bin/* docs/* obj/*

doc: 
	doxygen
