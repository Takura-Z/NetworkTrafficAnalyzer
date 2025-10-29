#include <QCoreApplication>
#include <QProcess>
#include <QStringList>
#include <QDebug>

// --- Configuration ---
// The path to your Python executable or just "python" if it's in your PATH.
const QString PYTHON_EXECUTABLE = "python";
// The path to the script you want to run.
const QString SCRIPT_PATH = "C:\\IDS_Powered_By_AI\\app.py";
// ---------------------

int main(int argc, char *argv[])
{
    // QCoreApplication is used for non-GUI applications (like this terminal example)
    QCoreApplication a(argc, argv);

    // 1. Prepare the command and arguments
    QString program = PYTHON_EXECUTABLE;
    QStringList arguments;
    arguments << SCRIPT_PATH;
    // Add any command-line arguments your Python script needs here:
    // arguments << "--option" << "value";

    // 2. Create and start a QProcess
    QProcess process;
    qDebug() << "Starting Python script:" << program << arguments;

    // Connect the finished signal to a lambda function to handle the process end
    QObject::connect(&process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                     [&](int exitCode, QProcess::ExitStatus exitStatus) {

                         qDebug() << "Python script finished with exit code:" << exitCode;
                         if (exitStatus == QProcess::NormalExit) {
                             qDebug() << "Script Output (Standard Output):\n" << process.readAllStandardOutput();

                             QByteArray errorOutput = process.readAllStandardError();
                             if (!errorOutput.isEmpty()) {
                                 qWarning() << "Script Output (Standard Error):\n" << errorOutput;
                             }
                         } else {
                             qCritical() << "Script crashed or finished abnormally. Standard Error:\n" << process.readAllStandardError();
                         }

                         // 3. Quit the QCoreApplication when the process is done
                         a.quit();
                     });

    // Start the process
    process.start(program, arguments);

    // Check if the process started successfully
    if (!process.waitForStarted(5000)) { // Wait up to 5 seconds
        qCritical() << "Failed to start Python executable:" << process.errorString();
        return 1; // Return non-zero to indicate an error
    }

    // Enter the Qt event loop. The application will run until a.quit() is called.
    return a.exec();
}
