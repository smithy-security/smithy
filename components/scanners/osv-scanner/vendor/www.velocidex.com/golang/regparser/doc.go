package regparser

/*

   This package is an implementation of a registry parser in Golang.

   The file format specification is explored in detail here:

   https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

   While the above reference discusses data structures by reversing
   the registry format, in this implementation we use the struct
   layouts and names as obtained from the Microsoft Symbol
   server. Therefore we try to stay as close as possible to the
   Microsoft struct names.

   In this implementation we add convenience methods to the original
   struct names as required. For example, we represent a key node
   using the symbol CM_KEY_NODE as found in the Symbol Server. We then
   add a method to this object to return all subkeys by parsing out
   the various indexing structures transparently Subkeys() which also
   returns a list of CM_KEY_NODE objects.

*/
