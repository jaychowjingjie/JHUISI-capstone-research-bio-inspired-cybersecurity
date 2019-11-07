// fuzzfier.h V. Rao, H. Rao
// program to fuzzify data
class category {
private:
  char name[30];
  float lowval,highval,midval;
public:
  category(){};
  void setname(char *);
  char * getname();
  void setval(float&,float&,float&);
  float getlowval();
  float getmidval();
  float gethighval();
  float getshare(const float&);
  ~category(){};
};
int randnum(int);
