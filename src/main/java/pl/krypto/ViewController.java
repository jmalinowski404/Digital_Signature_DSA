package pl.krypto;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import pl.krypto.*;

import static pl.krypto.Main.*;
import static pl.krypto.Utils.getFileHash;
import static pl.krypto.Utils.getSHA;

public class ViewController {
    private File dataFile;

    private File privateKeyFile;

    private File publicKeyFile;

    private BigInteger fM;
    private boolean didSucceed;

    private Main.InitParameters params;
    private Main.DocumentSignature ds;

    @FXML
    private Button savePrivateBtn;

    @FXML
    private Button savePublicBtn;

    @FXML
    private TextArea privateKeyTextArea;

    @FXML
    private TextArea publicKeyTextArea;

    @FXML
    private TextArea dataTextArea;

    @FXML
    private TextField privateKeyInput;

    @FXML
    private Label infoLabel;

    @FXML
    private Label infoLabel1;

    @FXML
    private Button loadDataFromFileBtn;

    @FXML
    private Button loadPrivateKeyFromFileBtn;

    @FXML
    private TextField publicKeyInput;

    @FXML
    private Button publicKeyInputFromFileBtn;

    @FXML
    private Button verifySignatureBtn;

    @FXML
    private Label statusBar;

    @FXML
    protected void loadPublicKeyFromFile() {
        publicKeyFile = onChooseFile(publicKeyInputFromFileBtn, "key");
    }

    @FXML
    protected void verifySignature() throws NoSuchAlgorithmException {
        if (ds == null) return;

        didSucceed = VerifySignature(ds.s1(), ds.s2(), params.q(), params.p(), params.h(), new BigInteger(publicKeyInput.getText().trim()), fM);

        if (didSucceed) {
            statusBar.setText("Sukces!");
        } else {
            statusBar.setText("Porazka...");
        }
    }

    @FXML
    protected void signData() throws NoSuchAlgorithmException, IOException {
        if (params == null || params.a() == null) {
            return;
        }

        if (dataFile != null) {
            fM = null;

            new Thread(() -> {
                try {
                    fM = getFileHash(dataFile.toPath());

                    ds = GenerateSignature(params.p(), params.q(), params.h(), params.a(), fM);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).start();
        } else if (!dataTextArea.getText().isEmpty()) {
            fM = null;
            String input = dataTextArea.getText();

            byte[] hashInput = getSHA("SHA-256", input);
            fM = new BigInteger(1, hashInput);

            ds = GenerateSignature(params.p(), params.q(), params.h(), params.a(), fM);
        }
    }

    @FXML
    protected void loadDataFromFile() {
        dataFile = onChooseFile(loadDataFromFileBtn, "data");
    }

    @FXML
    protected void loadPrivateKeyFromFile() {
        privateKeyFile = onChooseFile(loadPrivateKeyFromFileBtn, "key");
    }

    @FXML
    protected void generateKeys() {
        params = GenerateKeys(160, 1024);

        privateKeyTextArea.setText(params.a().toString());
        publicKeyTextArea.setText(params.b().toString());
    }

    @FXML
    protected void saveToFilePrivate() {
        byte[] data = privateKeyTextArea.getText().getBytes(StandardCharsets.UTF_8);

        saveToFile(data, "kluczPrywatny", savePrivateBtn);
    }

    @FXML
    protected void saveToFilePublic() {
        byte[] data = publicKeyTextArea.getText().getBytes(StandardCharsets.UTF_8);

        saveToFile(data, "kluczPubliczny", savePublicBtn);
    }

    protected File onChooseFile(Button btn, String opt) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wybierz plik do zaszyfrowania/zdeszyfrowania");

        Stage stage = (Stage) btn.getScene().getWindow();

        File file = fileChooser.showOpenDialog(stage);

        if (file != null) {
            if (opt.equals("key")) {
                infoLabel.setText("Załadowano plik z kluczem: " + file.getName());
            } else {
                infoLabel1.setText("Załadowano plik z danymi: " + file.getName());
            }

            return file;
        }
        return null;
    }

    protected void saveToFile(byte[] data, String suggestedFileName, Button button) {
        FileChooser fileChoose = new FileChooser();
        fileChoose.setTitle("Zapisz plik jako...");

        fileChoose.setInitialFileName(suggestedFileName);

        fileChoose.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Pliki zaszyfrowane (*.enc)", "*.enc"),
                new FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );

        Stage stage = (Stage) button.getScene().getWindow();

        File savedFile = fileChoose.showSaveDialog(stage);

        if (savedFile != null) {
            try {
                Files.write(savedFile.toPath(), data);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
