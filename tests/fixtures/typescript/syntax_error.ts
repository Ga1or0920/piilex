// File with intentional syntax errors to test parse warning output

interface User {
  email: string;
  phone: string;

// Missing closing brace for interface

function processUser(user: User) {
  const password = getPassword(;  // missing closing paren
  console.log(user.email);
}

const ssn = getSSN();
