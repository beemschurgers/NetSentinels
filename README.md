# NetSentinel - Network Security Monitoring & Threat Detection System

A comprehensive network security monitoring platform that combines real-time packet capture, machine learning-based threat detection, and an intuitive web-based dashboard for network administrators and security professionals.

## 🚀 Features

### Core Capabilities
- **Real-time Packet Capture**: Live network traffic monitoring using Scapy
- **AI-Powered Threat Detection**: Two-stage ML pipeline for network anomaly detection
- **Device Discovery**: Automatic network device detection and monitoring
- **Performance Monitoring**: System and network performance metrics
- **Interactive Dashboard**: Modern React-based web interface
- **Threat Logging**: Comprehensive threat logging with CSV and PCAP exports

### Security Features
- **Multi-stage ML Detection**: Stage 1 (threat classification) + Stage 2 (threat type identification)
- **Real-time Alerts**: WebSocket-based threat notifications
- **Flow-based Analysis**: Per-flow traffic analysis and threat detection
- **Protocol Analysis**: Deep packet inspection for various network protocols
- **Geographic Tracking**: Traffic source and destination analysis

### Dashboard Components
- **Network Overview**: Real-time network health and performance metrics
- **Threat Detection**: Live threat monitoring with severity classification
- **Device Management**: Network device discovery and status monitoring
- **Traffic Analytics**: Protocol distribution, top talkers, and bandwidth analysis
- **System Performance**: Network utilization tracking

## 🛠️ Installation & Setup

### Prerequisites
- **Anaconda or Miniconda**
- **Node.js 18+** with npm
- **Administrative privileges** (for packet capture)
- **Npcap** for packet capture. Download from [Npcap website](https://npcap.com).

### Conda on Windows (PATH setup)

If you are installing Anaconda/Miniconda on Windows and want `conda` available directly in PowerShell/Command Prompt:

- During installation, you can check the option to **Add Anaconda/Miniconda to my PATH environment variable**.
- If you did not check it, you have two easy alternatives:
  1. Use the bundled prompt and initialize your shell:
     ```powershell
     # Open "Anaconda Prompt" or "Miniconda Prompt" as your shell
     conda init powershell
     # Close and reopen PowerShell for changes to take effect
     ```
  2. Add PATH entries manually (per-user PATH):
     - `%USERPROFILE%\miniconda3` (or `%USERPROFILE%\anaconda3`)
     - `%USERPROFILE%\miniconda3\Scripts`
     - `%USERPROFILE%\miniconda3\Library\bin`
     - `%USERPROFILE%\miniconda3\condabin`

After this, verify installation:
```powershell
conda --version
```

### Quick Installation (Recommended)
- **Windows**: Double-click `easy-setup.bat` to automatically install all dependencies for both backend and frontend.

### Manual Installation

#### Backend Setup

1. **Navigate to backend directory**:
   ```bash
   cd backend
   ```

2. **Install Python dependencies using conda**:
 Create a conda environment from the requirements file:
   ```bash
   conda create --name netsentinel --file requirements.txt
   conda activate netsentinel
   ```

3. **Ensure ML models are present**:
   - Place `stage1_model.pkl` and `stage2_model.pkl` in the `model/` directory
   - These models should be trained for your specific network environment

4. **Run the backend server**:
     ```bash
     start.bat
     ```
   The backend will start on `http://localhost:8000`

#### Frontend Setup

1. **Navigate to frontend directory**:
   ```bash
   cd frontend
   ```

2. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

3. **Start the development server**:
   ```bash
   npm run dev
   ```
   The frontend will start on `http://localhost:3000`

### Quick Start

  1. Run the main start script:
     ```bash
     start.bat
     ```
     This will automatically start both frontend and backend services.
