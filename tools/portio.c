#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define BASEPORT 0x105 /*  a random port */

int main()
{
  /* Get access to the ports */
  if (ioperm(BASEPORT, 3, 1))
  {
      perror("ioperm");
      exit(1);
  }
  
  /* Set the data signals (D0-7) of the port to all low (0) */
  outb(0, BASEPORT);
  
  /* Sleep for a while (100 ms) */
  usleep(1000000);
  
  /* Read from the status port (BASE+1) and display the result */
  printf("status: %d\n", inb(BASEPORT + 1));

  /* We don't need the ports anymore */
  if (ioperm(BASEPORT, 3, 0))
  {
      perror("ioperm");
      exit(1);
  }

  exit(0);
}

