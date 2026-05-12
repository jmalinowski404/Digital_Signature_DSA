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

import org.w3c.dom.Text;
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
    private TextField s1Field;

    @FXML
    private TextField s2Field;

    @FXML
    private TextField pField;

    @FXML
    private TextField qField;

    @FXML
    private TextField hField;

    @FXML
    private TextArea pArea;

    @FXML
    private TextArea qArea;

    @FXML
    private TextArea hArea;

    @FXML
    private TextArea s1TextArea;

    @FXML
    private TextArea s2TextArea;

    @FXML
    protected void loadPublicKeyFromFile() throws IOException {
        publicKeyFile = onChooseFile(publicKeyInputFromFileBtn, "key");
        if (publicKeyFile != null) {
            try {
                String content = Files.readString(publicKeyFile.toPath(), StandardCharsets.UTF_8);
                String[] lines = content.split("\n");

                if (lines.length >= 4) {
                    publicKeyInput.setText(lines[0].trim());
                    pField.setText(lines[1].trim());
                    qField.setText(lines[2].trim());
                    hField.setText(lines[3].trim());
                    statusBar.setText("Załadowano klucz i parametry domeny!");
                } else {
                    statusBar.setText("BŁĄD: Plik z kluczem jest uszkodzony lub niekompletny.");
                }
            } catch (IOException e) {
                statusBar.setText("Błąd podczas odczytu pliku klucza!");
                e.printStackTrace();
            }
        }
    }

    @FXML
    protected void verifySignature() throws NoSuchAlgorithmException {
        if (s1Field.getText().trim().isEmpty() || s2Field.getText().trim().isEmpty()) {
            statusBar.setText("BŁĄD: Podaj wartości podpisu S1 i S2!");
            return;
        }

        BigInteger s1Input = new BigInteger(s1Field.getText().trim());
        BigInteger s2Input = new BigInteger(s2Field.getText().trim());

        BigInteger pubKeyB = new BigInteger(publicKeyInput.getText().trim());
        BigInteger pParam = new BigInteger(pField.getText().trim());
        BigInteger qParam = new BigInteger(qField.getText().trim());
        BigInteger hParam = new BigInteger(hField.getText().trim());

        BigInteger currentHash;
        if (dataFile != null) {
            try { currentHash = getFileHash(dataFile.toPath()); }
            catch (Exception e) { throw new RuntimeException(e); }
        } else {
            byte[] hashInput = getSHA("SHA-256", dataTextArea.getText());
            currentHash = new BigInteger(1, hashInput);
        }

        didSucceed = VerifySignature(s1Input, s2Input, qParam, pParam, hParam, pubKeyB, currentHash);

        statusBar.setText(didSucceed ? "Sukces!" : "Porażka...");
    }

    @FXML
    protected void signData() throws NoSuchAlgorithmException, IOException {
        if (privateKeyInput.getText().trim().isEmpty() || pArea.getText().trim().isEmpty()) {
            infoLabel.setText("BŁĄD: Wczytaj klucz prywatny i parametry!");
            return;
        }

        final BigInteger privateA = new BigInteger(privateKeyInput.getText().trim());
        final BigInteger pParam = new BigInteger(pArea.getText().trim());
        final BigInteger qParam = new BigInteger(qArea.getText().trim());
        final BigInteger hParam = new BigInteger(hArea.getText().trim());

        if (dataFile != null) {
            fM = null;

            new Thread(() -> {
                try {
                    fM = getFileHash(dataFile.toPath());

                    ds = GenerateSignature(pParam, qParam, hParam, privateA, fM);

                    javafx.application.Platform.runLater(() -> {
                        s1TextArea.setText(ds.s1().toString());
                        s2TextArea.setText(ds.s2().toString());
                    });
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).start();
        } else if (!dataTextArea.getText().isEmpty()) {
            fM = null;
            String input = dataTextArea.getText();

            byte[] hashInput = getSHA("SHA-256", input);
            fM = new BigInteger(1, hashInput);

            ds = GenerateSignature(pParam, qParam, hParam, privateA, fM);

            s1TextArea.setText(ds.s1().toString());
            s2TextArea.setText(ds.s2().toString());
        }
    }

    @FXML
    protected void loadDataFromFile() {
        dataFile = onChooseFile(loadDataFromFileBtn, "data");
    }

    @FXML
    protected void loadPrivateKeyFromFile() throws IOException {
        privateKeyFile = onChooseFile(loadPrivateKeyFromFileBtn, "key");
        privateKeyInput.setText(Files.readString(privateKeyFile.toPath(), StandardCharsets.UTF_8));
    }

    @FXML
    protected void generateKeys() {
        params = GenerateKeys(160, 1024);

        privateKeyTextArea.setText(params.a().toString());
        publicKeyTextArea.setText(params.b().toString());

        pArea.setText(params.p().toString());
        qArea.setText(params.q().toString());
        hArea.setText(params.h().toString());
    }

    @FXML
    protected void saveToFilePrivate() {
        if (params == null || params.a() == null) return;

        String exportData = params.a().toString();

        byte[] data = exportData.getBytes(StandardCharsets.UTF_8);
        saveToFile(data, "kluczPrywatny", savePrivateBtn);
    }

    @FXML
    protected void saveToFilePublic() {
        String exportData = String.join("\n",
                publicKeyTextArea.getText().trim(),
                pArea.getText().trim(),
                qArea.getText().trim(),
                hArea.getText().trim()
        );

        byte[] data = exportData.getBytes(StandardCharsets.UTF_8);

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
                new FileChooser.ExtensionFilter("Pliki tekstowe", "*.txt"),
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
