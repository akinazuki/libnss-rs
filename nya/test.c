#include <stdio.h>
#include <shadow.h>
#include <pwd.h>
#include <sys/types.h>
#include <errno.h>
int main(int argc, char *argv[])
{
  // struct passwd *pw;
  // printf("testing getpwent()...\n");
  // while ((pw = getpwent()) != NULL) {
  //   //shadow
  //   struct spwd *sp;
  //   sp = getspnam(pw->pw_name);
  //   if (sp != NULL) {
  //     printf("name: %s\n", pw->pw_name);
  //     printf(" - shadow: %s\n\n", sp->sp_pwdp);
  //   }
  // };
  struct passwd *test_pw;
  struct spwd *test_sp;
  char *username = argv[1] ? argv[1] : "root";
  test_pw = getpwnam(username);
  test_sp = getspnam(username);
  printf("\ntesting getpwnam(%s)...\n\n", username);
  if (test_pw != NULL) {
    printf("name: %s\n", test_pw->pw_name);
    printf("uid: %d, gid: %d\n", test_pw->pw_uid, test_pw->pw_gid);
    printf("dir: %s\n", test_pw->pw_dir);
    if (test_sp != NULL) {
      printf("shadow: %s\n", test_sp->sp_pwdp);
    }else{
      printf("shadow get failed: %d\n", errno);
    }
  }
  endpwent();
  return 0;
}