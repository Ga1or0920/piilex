package com.example;

import java.util.logging.Logger;

public class SimplePii {
    private static final Logger logger = Logger.getLogger(SimplePii.class.getName());

    private String email;
    private String fullName;
    private String phoneNumber;
    private String ssn;
    private String password;

    public SimplePii(String email, String fullName, String phoneNumber) {
        this.email = email;
        this.fullName = fullName;
        this.phoneNumber = phoneNumber;
    }

    public void processUser() {
        logger.info("Processing user: " + this.email);
        System.out.println(this.fullName);

        String creditCard = getCreditCard();
        db.save(this.email, this.ssn);
    }

    public String getEmail() {
        return this.email;
    }

    private String getCreditCard() {
        return "4111111111111111";
    }
}
