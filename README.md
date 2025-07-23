# ReADSaFe  
### Reliable Multi-Receiver Anonymous Data Sharing Protocol with Fine-Grained Access in Clouds-Assisted IoT-Edge Environment

This edge-side implementation ensures that data is encrypted before being reliably and anonymously uploaded to cloud storage, enabling secure multi-receiver sharing with fine-grained access control.

---

## 📁 File Overview

This project contains two independent Java programs:

- **`EdgeController.java`**  
  This is the main component used to verify the correctness of the proposed protocol and to evaluate the time performance of various steps and algorithms.

- **`dropbox.java`**  
  This component can be used separately for uploading or downloading files to/from Dropbox cloud storage. It is not integrated into the main flow but may be used in conjunction for storage testing.

---

## 🛠 Prerequisites

Note: The project has been developed and tested using the environment below.

- **Java Version**: OpenJDK 21.0.1  
- **IDE Recommended**: Visual Studio Code (with [Java Extension Pack](https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-pack))

---

## 📦 Dependencies

All required `.jar` libraries are listed in `.vscode/settings.json` to ensure all `import` statements are resolved without issue.

**Note:** Please modify the path according to your own system.

---

## 🚀 How to Run

You can run the project directly using **Visual Studio Code**:

1. Open the project folder in VS Code.
2. Ensure all required `.jar` files are properly referenced in `.vscode/settings.json`.
3. Open the desired Java file (e.g., `EdgeController.java`).
4. Click the **"Run Java"** button in the top-right corner of the editor.

Make sure you have installed the [Java Extension Pack](https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-pack) in VS Code.

---

## 📎 Notes

- Please make sure to update the **path and filename references** in both `EdgeController.java` and `dropbox.java` according to your system.
- Additionally, you must replace the default token string in `dropbox.java` with **your own Dropbox Access Token** in order for the upload/download functionality to work.

---

## 📷 Sample Output

Below is a sample output from running `EdgeController.java` in the VS Code terminal:

![imgae](https://i.postimg.cc/P5Fw2wJC/Screenshot-2025-07-23-174434.png)
