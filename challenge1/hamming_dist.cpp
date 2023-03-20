#include <iostream>
#include <cstdint>
#include <string>
using namespace std;


int popcount(int x)
{
  int tot = 0;
  while (x)
    {
      tot++; x &= x-1;
    }
  return tot;
}

int64_t hamming_distance(const string &s1, const string &s2)
{
  int64_t res = 0;
  for (size_t i = 0; i < s1.size(); i++) {
    res += popcount(s1[i] ^ s2[i]);
  }
  return res;
}

int main ()
{
  string s = "this is a test";
  string t = "wokka wokka!!!";
  cout << hamming_distance(s, t) << "\n";
}

