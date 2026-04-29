module Kryptografia {
    requires javafx.controls;
    requires javafx.graphics;
    requires java.desktop;
    requires java.sql;
    requires javafx.fxml;

    opens pl.krypto to javafx.fxml;
    exports pl.krypto;
}