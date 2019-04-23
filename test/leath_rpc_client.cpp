
#include "precompiled.h"

extern "C" int leath_client( int argc, char* argv[] );

int main(int argc, char* argv[])
{
  int rv = 0;

  leath_client(argc, argv);

	return rv;
}

