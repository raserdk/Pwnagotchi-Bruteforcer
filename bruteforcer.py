
import os
import json
import time
import logging
import threading
import subprocess
import re
from typing import Set, Optional
from flask import Flask, render_template, request, redirect, url_for

import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK


class BruteForce(plugins.Plugin):
    __author__ = 'SKY'
    __version__ = '2.0.0'
    __license__ = 'GPL3'
    __description__ = 'A plugin to brute force WPA handshakes using aircrack-ng.'

    def __init__(self):
        # Initialize attributes that do not depend on configuration options
        self.status = "IDLE"
        self.progress = "0%"
        self.result = ""
        self.ui = None
        self.lock = threading.Lock()
        self.processed_files = 0
        self.total_files = 0
        self.cracked_count = 0
        self.failed_count = 0
        self.words_processed = 0  # Initialize words_processed attribute
        self.current_task: Optional[subprocess.Popen] = None
        self.progress_file = "/root/bruteforce_progress.json"
        self.processed_files_set: Set[str] = set()
        self.stop_event = threading.Event()
        self.retry_limit = 3
        self.status_message = ""  # Holds the small status message for display
        self.template_folder = '/usr/local/share/pwnagotchi/custom-plugins'
        self.dashboard_template = os.path.join(self.template_folder, 'dashboard.html')

        # Check if dashboard.html exists; if not, create it
        self.create_dashboard_template_if_missing()

        self.app = Flask(__name__, template_folder=self.template_folder)
        self.dashboard_thread = threading.Thread(target=self.start_dashboard)
        self.dashboard_thread.daemon = True

        # Initialize wordlist selection
        self.selected_wordlist = None  # This will store the selected wordlist
        self.wordlist_folder = "/home/pi/wordlists"
        self.wordlist_files = self.load_wordlists()

    def create_dashboard_template_if_missing(self):
        # Check if the template file exists
        if not os.path.exists(self.dashboard_template):
            os.makedirs(self.template_folder, exist_ok=True)  # Ensure the template folder exists
            with open(self.dashboard_template, 'w') as f:
                # Write a basic HTML structure for the dashboard
                f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BruteForce Dashboard</title>
</head>
<body>
    <h1>BruteForce Plugin Dashboard</h1>
    <p><strong>Status:</strong> {{ status }}</p>
    <p><strong>Progress:</strong> {{ progress }}</p>
    <p><strong>Processed Files:</strong> {{ processed_files }} / {{ total_files }}</p>
    <p><strong>Words Processed:</strong> {{ words_processed }}</p>
    <p><strong>Cracked Count:</strong> {{ cracked_count }}</p>
    <p><strong>Failed Count:</strong> {{ failed_count }}</p>

    <h2>Select Wordlist</h2>
    <form action="/set_wordlist" method="post">
        <label for="wordlist">Choose a wordlist:</label>
        <select name="wordlist" id="wordlist">
            {% for wordlist in wordlists %}
                <option value="{{ wordlist }}" {% if wordlist == selected_wordlist %}selected{% endif %}>{{ wordlist }}</option>
            {% endfor %}
        </select>
        <button type="submit">Set Wordlist</button>
    </form>
</body>
</html>
''')
            logging.info("[bruteforce] Created default dashboard.html template.")
        else:
            logging.info("[bruteforce] dashboard.html template already exists.")

    def load_wordlists(self):
        """
        Loads all wordlist files from the specified directory.

        Returns:
            list: A list of wordlist filenames.
        """
        return [
            f for f in os.listdir(self.wordlist_folder)
            if os.path.isfile(os.path.join(self.wordlist_folder, f))
        ]

    def on_configure(self, options):
        # Access configuration options
        self.options = options
        self.wordlist_folder = self.options.get("wordlist_folder", "/home/pi/wordlists/bt4_passwords.txt")
        self.handshake_dir = self.options.get("handshake_dir", "/home/pi/handshakes")
        self.delay_between_attempts = self.options.get("delay_between_attempts", 5)  # Ensure it's set

    def on_loaded(self):
        logging.info("[bruteforce] Plugin loaded.")
        self.load_progress()

        # Start the Flask web server for the dashboard
        self.dashboard_thread.start()

        self.update_total_files()
        self.start_monitoring()

    def start_dashboard(self):
        @self.app.route('/')
        def dashboard():
            return render_template('dashboard.html', 
                                   status=self.status,
                                   progress=self.progress,
                                   processed_files=self.processed_files,
                                   total_files=self.total_files,
                                   words_processed=self.words_processed,
                                   wordlists=self.wordlist_files,
                                   selected_wordlist=self.selected_wordlist,
                                   cracked_count=self.cracked_count,
                                   failed_count=self.failed_count)

        @self.app.route('/set_wordlist', methods=['POST'])
        def set_wordlist():
            self.selected_wordlist = request.form['wordlist']
            logging.info(f"[bruteforce] Wordlist selected: {self.selected_wordlist}")
            return redirect(url_for('dashboard'))

        # Start the Flask web server
        self.app.run(host='0.0.0.0', port=5000)

    def on_unloaded(self):
        logging.info("[bruteforce] Plugin unloaded.")
        self.stop_event.set()

    def on_ui_setup(self, ui):
        self.ui = ui
        ui_elements = {
            "bruteforce_status": ("BF:", self.status, (128, 60)),
            "bruteforce_progress": ("PR:", self.progress, (188, 60)),
            "bruteforce_result": ("RE:", self.result, (128, 68)),
            "bruteforce_total": ("TO:", f"{min(self.processed_files, self.total_files)}/{self.total_files}", (188, 68)),
            "bruteforce_cracked": ("CR:", f"{self.cracked_count}/{self.processed_files}", (133, 1)),
            # Status message at the bottom center with a smaller font size
            "bruteforce_step": ("", "Idle", (1, 13))  # Position this in the bottom center
        }
        for key, (label, value, position) in ui_elements.items():
            ui.add_element(
                key,
                LabeledValue(
                    color=BLACK,
                    label=label,
                    value=value,
                    position=position,
                    label_font=fonts.Bold,  # Bold for labels
                    text_font=fonts.Small,  # Use smaller font for the step status
                ),
            )

    def on_ui_update(self, ui):
        if self.ui:
            with self.ui._lock:
                ui.set("bruteforce_status", self.status)
                ui.set("bruteforce_progress", self.progress)
                ui.set("bruteforce_result", self.result)
                ui.set("bruteforce_total", f"{min(self.processed_files, self.total_files)}/{self.total_files}")
                ui.set("bruteforce_cracked", f"{self.cracked_count}/{self.processed_files}")
                ui.set("bruteforce_step", self.status_message)  # Small status message

    def start_monitoring(self):
        logging.info("[bruteforce] Starting handshake monitoring thread.")
        threading.Thread(target=self.monitor_handshakes, daemon=True).start()

    def monitor_handshakes(self):
        while not self.stop_event.is_set():
            new_files = self.get_new_handshakes()
            for pcap_file in new_files:
                self.run_bruteforce(pcap_file)
                time.sleep(self.delay_between_attempts)
            time.sleep(10)

    def get_new_handshakes(self) -> Set[str]:
        """
        Retrieves a set of new handshake files that have not been processed yet.

        Returns:
            Set[str]: A set containing the file paths of new .pcap files.
        """
        all_pcap_files = {
            os.path.join(root, file)
            for root, _, files in os.walk(self.handshake_dir)
            for file in files if file.endswith(".pcap")
        }
        new_files = all_pcap_files - self.processed_files_set
        return new_files

    def run_bruteforce(self, pcap_file, retries=0):
        with self.lock:
            # Ensure only one instance of the brute forcer runs
            if self.current_task is not None:
                return  # Exit if a task is already running

            # Start brute-forcing the current pcap file
            self.processed_files_set.add(pcap_file)

            # Extract SSID and validate filename format
            if "_" in os.path.basename(pcap_file):
                ssid = os.path.basename(pcap_file).split("_")[0]
            else:
                ssid = "Unknown"
            self.status = f"Processing {ssid}..."
            self.update_progress(0, 0)

            wordlist_path = os.path.join(self.wordlist_folder, self.selected_wordlist)
            logging.info(f"[bruteforce] Starting brute force for {pcap_file} with wordlist {self.selected_wordlist}...")

            # Build the brute force command using aircrack-ng
            command = [
                "aircrack-ng", 
                "-w", wordlist_path, 
                "-b", ssid, 
                pcap_file
            ]
            try:
                self.current_task = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.monitor_bruteforce_output(self.current_task)
                self.current_task.wait()
            except Exception as e:
                logging.error(f"[bruteforce] Error during brute force: {e}")
                self.failed_count += 1
                if retries < self.retry_limit:
                    self.run_bruteforce(pcap_file, retries + 1)
                else:
                    self.status = "Failed to crack"
                    self.failed_count += 1
            finally:
                self.current_task = None

    def monitor_bruteforce_output(self, task: subprocess.Popen):
        while task.poll() is None:
            output = task.stdout.readline().decode()
            if output:
                self.process_output(output)
            time.sleep(0.1)

    def process_output(self, output: str):
        if "key found" in output:
            self.status = "Key Found!"
            self.cracked_count += 1
            self.result = output.strip()
        elif "%" in output:
            # Update progress based on the output of aircrack-ng
            match = re.search(r"(\d+)%", output)
            if match:
                self.progress = f"{match.group(1)}%"
        self.update_progress(self.processed_files, self.total_files)

    def update_progress(self, processed_files, total_files):
        """
        Update progress information to save to the progress file.
        """
        self.processed_files = processed_files
        self.total_files = total_files
        self.words_processed = 0  # Reset words processed here, if needed
        self.save_progress()

    def load_progress(self):
        """
        Load progress from the file, if it exists.
        """
        if os.path.exists(self.progress_file):
            with open(self.progress_file, "r") as f:
                data = json.load(f)
                self.processed_files = data.get("processed_files", 0)
                self.total_files = data.get("total_files", 0)
                self.cracked_count = data.get("cracked_count", 0)
                self.failed_count = data.get("failed_count", 0)

    def save_progress(self):
        try:
            with open(self.progress_file, 'w') as f:
                json.dump({
                    "processed_files": list(self.processed_files_set),
                    "total_files": self.total_files,
                    "cracked_count": self.cracked_count,
                    "words_processed": self.words_processed,
                    "wps_data": self.wps_data,
                    "elapsed_time_data": self.elapsed_time_data,
                    "time_labels": self.time_labels,
                    "handshake_ssids": self.handshake_ssids,
                    "progress_data": self.progress_data,
                }, f)
        except Exception as e:
            logging.error(f"[bruteforce] Error saving progress: {e}")

    def load_progress(self):
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r') as f:
                    data = json.load(f)
                    self.processed_files_set = set(data.get("processed_files", []))
                    self.total_files = data.get("total_files", 0)
                    self.cracked_count = data.get("cracked_count", 0)
                    self.words_processed = data.get("words_processed", 0)
                    self.wps_data = data.get("wps_data", [])
                    self.elapsed_time_data = data.get("elapsed_time_data", [])
                    self.time_labels = data.get("time_labels", [])
                    self.handshake_ssids = data.get("handshake_ssids", [])
                    self.progress_data = data.get("progress_data", [])
            except Exception as e:
                logging.error(f"[bruteforce] Error loading progress: {e}")
        else:
            logging.info("[bruteforce] No saved progress found.")

    def reset_progress(self):
        """
        Deletes the saved progress by removing the progress file.
        """
        try:
            if os.path.exists(self.progress_file):
                os.remove(self.progress_file)
                logging.info("[bruteforce] Progress reset. Progress file deleted.")
                self.processed_files = 0
                self.cracked_count = 0
                self.words_processed = 0
                self.words_processed_abbr = ""
                self.processed_files_set.clear()
                self.on_ui_update(self.ui)  # Update the UI after reset
            else:
                logging.info("[bruteforce] No progress file found to delete.")
        except Exception as e:
            logging.error(f"[bruteforce] Failed to delete progress file: {e}")
