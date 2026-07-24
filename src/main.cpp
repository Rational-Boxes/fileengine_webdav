// Copyright (C) 2026 James Hickman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <signal.h>
#include <fstream>
#include <cstdlib>
#include <Poco/Util/Application.h>
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionSet.h>
#include <Poco/Util/HelpFormatter.h>
#include <Poco/Util/AbstractConfiguration.h>
#include <Poco/File.h>
#include <Poco/Path.h>
#include <Poco/Environment.h>

#include "webdav_server.h"
#include "utils.h"

// Global flag to control server shutdown
volatile sig_atomic_t server_running = 1;

void signal_handler(int signal) {
    server_running = 0;
}

// Function to load environment variables from .env file
void loadEnvFile() {
    std::ifstream file(".env");
    if (!file.is_open()) {
        // Try alternative locations
        file.open("../.env");
        if (!file.is_open()) {
            std::cerr << "Warning: Could not open .env file" << std::endl;
            return;
        }
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue; // Skip empty lines and comments
        }

        size_t equalsPos = line.find('=');
        if (equalsPos != std::string::npos) {
            std::string key = line.substr(0, equalsPos);
            std::string value = line.substr(equalsPos + 1);

            // Remove quotes if present
            if (value.length() >= 2 &&
                ((value.front() == '"' && value.back() == '"') ||
                 (value.front() == '\'' && value.back() == '\''))) {
                value = value.substr(1, value.length() - 2);
            }

            // Set the environment variable
            setenv(key.c_str(), value.c_str(), 1);
        }
    }
}

using Option = Poco::Util::Option;
using OptionSet = Poco::Util::OptionSet;
using Application = Poco::Util::Application;

namespace webdav {

class WebDAVApplication : public Poco::Util::Application {
public:
    WebDAVApplication() : _helpRequested(false) {
    }

    ~WebDAVApplication() {
    }

protected:
    void initialize(Application& self) {
        loadConfiguration(); // load default configuration files, if present
        Application::initialize(self);
    }

    void uninitialize() {
        Application::uninitialize();
    }

    void defineOptions(OptionSet& options) {
        Application::defineOptions(options);

        options.addOption(
            Option("help", "h", "Display help information on command line arguments.")
                .required(false)
                .repeatable(false));

        options.addOption(
            Option("config", "c", "Load configuration data from a file.")
                .required(false)
                .repeatable(false)
                .argument("file"));
    }

    void handleOption(const std::string& name, const std::string& value) {
        Application::handleOption(name, value);

        if (name == "help")
            _helpRequested = true;
        else if (name == "config")
            loadConfiguration(value);
    }

    void displayHelp() {
        Poco::Util::HelpFormatter helpFormatter(options());
        helpFormatter.setCommand(commandName());
        helpFormatter.setUsage("OPTIONS");
        helpFormatter.setHeader("A WebDAV server that exposes the FileEngine gRPC filesystem API.");
        helpFormatter.format(std::cout);
    }

    int main(const std::vector<std::string>& args) {
        if (_helpRequested) {
            displayHelp();
        } else {
            // Get host and port from configuration or environment variables
            std::string host = config().getString("webdav.host", webdav::getEnvOrDefault("WEBDAV_HOST", "0.0.0.0"));
            int port = config().getInt("webdav.port", std::stoi(webdav::getEnvOrDefault("WEBDAV_PORT", "8080")));

            // Log startup message
            if (webdav::shouldLogToConsole()) {
                webdav::logMessage("INFO", "Starting WebDAV server on " + host + ":" + std::to_string(port));
            }

            // Create and start the WebDAV server
            std::unique_ptr<webdav::WebDAVServer> server = std::make_unique<webdav::WebDAVServer>(host, port);
            server->start();

            // Set up signal handling for graceful shutdown
            signal(SIGINT, signal_handler);
            signal(SIGTERM, signal_handler);

            // Keep the server running until a signal is received
            while (server_running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Sleep briefly to allow signal handling
            }

            // Log shutdown message
            if (webdav::shouldLogToConsole()) {
                webdav::logMessage("INFO", "Shutting down WebDAV server");
            }

            server->stop();
            server.reset(); // Explicitly reset to ensure proper cleanup
        }
        return Application::EXIT_OK;
    }

// No custom run method needed since Application::run() doesn't take arguments

private:
    bool _helpRequested;
};

} // namespace webdav

int main(int argc, char** argv) {
    // Load environment variables from .env file
    loadEnvFile();

    webdav::WebDAVApplication app;
    try {
        std::cout << "[DEBUG] Initializing WebDAV application..." << std::endl;
        app.init(argc, argv);
        std::cout << "[DEBUG] Running WebDAV application..." << std::endl;
        int result = app.run();
        std::cout << "[DEBUG] WebDAV application finished with result: " << result << std::endl;
        return result;
    } catch (Poco::Exception& exc) {
        std::cerr << "[ERROR] Poco::Exception caught: " << exc.displayText() << std::endl;
        return Poco::Util::Application::EXIT_SOFTWARE;
    } catch (const std::exception& exc) {
        std::cerr << "[ERROR] std::exception caught: " << exc.what() << std::endl;
        return Poco::Util::Application::EXIT_SOFTWARE;
    } catch (...) {
        std::cerr << "[ERROR] Unknown exception caught in main" << std::endl;
        return Poco::Util::Application::EXIT_SOFTWARE;
    }
}