#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>

int main(int argc, char const *argv[]) {
    time_t begin = time(NULL),
           loop = time(NULL) - 1;
    long count = 0;
    long num_msgs = 1000000;

    while (time(NULL) - begin < 60) {
        if (time(NULL) - loop > 0) {
            count = 0;
            loop = time(NULL);
        }
        
        while (count < num_msgs) {
            if (time(NULL) - loop > 0) {
                count = 0;
                loop = time(NULL);
                break;
            }
            printf("%ld: Sent %ld\n", time(NULL), count + 1);
            usleep(100);
            count++;
        }
    }

    return 0;
}
