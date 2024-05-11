package com.udacity.jwdnd.course1.cloudstorage.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private Integer userId;

    private String username;

    private String password;

    private String firstName;

    private String lastName;

    private String salt;

    public User(String username, String encodedSalt, String hashedPassword, String firstName, String lastName) {
        this.username = username;
        this.salt=encodedSalt;
        this.password=hashedPassword;
        this.firstName=firstName;
        this.lastName=lastName;
    }

}
