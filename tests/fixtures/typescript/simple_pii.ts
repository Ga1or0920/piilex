interface User {
  email: string;
  fullName: string;
  age: number;
  ipAddress: string;
  dateOfBirth: string;
}

const password = process.env.DB_PASSWORD;
let creditCard = getCreditCardFromInput();

function processUser(user: User) {
  console.log(`Processing user: ${user.email}`);
  logger.info(`User logged in from ${user.ipAddress}`);

  db.save({
    email: user.email,
    name: user.fullName,
  });

  fetch("https://api.analytics.com/track", {
    method: "POST",
    body: JSON.stringify({ email: user.email }),
  });

  res.json({
    user: {
      email: user.email,
      name: user.fullName,
    },
  });
}

const ssn = getUserSSN();
const phone_number = getPhoneNumber();
