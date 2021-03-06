// fuzzfier.cpp V. Rao, H. Rao
// program to fuzzify data
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "main.h"

using namespace std;

void category::setname(char *n) {
  strcpy(name,n);
}
char * category::getname() {
  return name;
}
void category::setval(float &h, float &m, float &l) {
  highval=h;
  midval=m;
  lowval=l;
}
float category::getlowval() {
  return lowval;
}
float category::getmidval() {
  return midval;
}
float category::gethighval() {
  return highval;
}
float category::getshare(const float & input) {
  // this member function returns the relative membership
  // of an input in a category, with a maximum of 1.0
  float output;
  float midlow;
  float highmid;
  float midval = getmidval();
  float highval = gethighval();
  midlow = midval - lowval;
  highmid = highval - midval;
  // if outside the range, then output=0
  if ((input <= lowval) || (input >= highval)) {
    output = 0;
  }
  else {
    if (input > midval)
      output = (highval - input) / highmid;
    else
      if (input==midval)
        output=1.0;
      else
        output = (input - lowval) / midlow;
  }
  return output;
}
int randomnum(int maxval) {
  // random number generator
  // will return an integer up to maxval
  srand ((unsigned)time(NULL));
  return rand() % maxval;
}

int main() {
  // a fuzzifier program that takes category information:
  // lowval, midval and highval and category name
  // and fuzzifies an input based on
  // the total number of categories and the membership
  // in each category
  int i=0,j=0,numcat=0,randnum;
  float l,m,h, inval=1.0;
  char input[30]=" ";
  category * ptr[10];
  float relprob[10];
  float total=0, runtotal=0;
  //input the category information; terminate with `done';
  while (1)
  {
    cout << "\nPlease type in a category name, e.g. Cool\n";
    cout << "Enter one word without spaces\n";
    cout << "When you are done, type `done' :\n\n";
    ptr[i]= new category;
    cin >> input;
    if ((input[0]=='d' && input[1]=='o' &&
         input[2]=='n' && input[3]=='e')) break;
    ptr[i] -> setname(input);
    cout << "\nType in the lowval, midval and highval\n";
    cout << "for each category, separated by spaces\n";
    cout << " e.g. 1.0 3.0 5.0 :\n\n";
    cin >> l >> m >> h;
    ptr[i] -> setval(h,m,l);
    i++;
  }
  numcat=i; // number of categories
  
  // Categories set up: Now input the data to fuzzify
  cout <<"\n\n";
  cout << "===================================\n";
  cout << "==Fuzzifier is ready for data==\n";
  cout << "===================================\n";
  while (1) {
    cout << "\ninput a data value, type 0 to terminate\n";
    cin >> inval;
    if (inval == 0) break;
    // calculate relative probabilities of
    // input being in each category
    total=0;
    for (j=0;j<numcat;j++)
    {
      relprob[j]=100*ptr[j] -> getshare(inval);
      total+=relprob[j];
    }
    if (total==0)
    {
      cout << "data out of range\n";
      exit(1);
    }
    randnum=randomnum((int)total);
    j=0;
    runtotal=relprob[0];
    while ((runtotal<randnum)&&(j<numcat))
    {
      j++;
      runtotal += relprob[j];
    }
    cout << "\nOutput fuzzy category is ==> " <<
    ptr[j] -> getname()<<"<== \n";
    cout <<"category\t"<<"membership\n";
    cout <<"−−−−−−−−−−−−−−−\n";
    for (j=0;j<numcat;j++)
    {
      cout << ptr[j] -> getname()<<"\t\t"<<
      (relprob[j]/total) <<"\n";
    }
  }
  cout << "\n\nAll done. Have a fuzzy day !\n";
}

