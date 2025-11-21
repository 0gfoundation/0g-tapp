# 0G Tapp

0G Tapp is a Trusted Application Platform that provides secure application deployment and execution within Trusted Execution Environments (TEE). It enables confidential computing with runtime measurement and attestation capabilities.

## Features

- **TEE-based Execution**: Run applications in secure enclaves (TDX, SEV, SGX)
- **Runtime Measurement**: Cryptographic measurement of application deployments
- **Remote Attestation**: Generate and verify attestation evidence
- **Docker Compose Integration**: Deploy containerized applications easily
- **gRPC API**: Comprehensive API for application lifecycle management
- **API Key Authentication**: Secure access control for sensitive operations

## Getting Started

### Prerequisites

- Alibaba Cloud account (for confidential computing instances)
- Docker and Docker Compose
- grpcurl (for testing)
- Rust toolchain (for building from source)

### Creating a Confidential Computing Instance

To run 0G Tapp, you need to create an Alibaba Cloud ECS instance with confidential computing support.

#### Step 1: Import the Confidential Image

1. Navigate to [Alibaba Cloud Custom Image Import](https://www.alibabacloud.com/help/en/ecs/user-guide/import-a-custom-image#a79650c1bdp04)

2. Import the confidential image with the following parameters:
   - **Image File URL**: `https://confidential-disk.oss-cn-beijing.aliyuncs.com/0g-tapp-confidential-gpu.qcow2`
   - **Operating System Type**: Linux
   - **Operating System Version**: Aliyun
   - **Architecture**: 64-bit Operating System
   - **Boot Mode**: UEFI
   - **Image Format**: QCOW2

#### Step 2: Configure NVMe Driver Support

After the image import completes:
1. Go to the image details page
2. Change **NVMe Driver** setting to **Supported**

#### Step 3: Create ECS Instance

Create a new ECS instance with the following specifications:
- **Region**: China (Beijing) - Zone L
- **Instance Type**: `ecs.gn8v-tee.4xlarge`
- **Image**: Select the imported confidential image

Once the instance is created and running, 0G Tapp service will start automatically.

### Deploying Applications on 0G Tapp

#### Starting an Application

Use the provided example script to deploy an application:

```bash
# Basic usage (connects to your-cvm-instance-host:port)
./examples/start_app.sh

# Custom host and port
./examples/start_app.sh <HOST> <PORT> <APP_ID> <DEPLOYER_HEX> <COMPOSE_FILE> <CONFIG_FILE> <API_KEY> 

# Example
./examples/start_app.sh your-cvm-instance-host port your-app-id 0xbae50462... ./docker_compose.yml ./config.yml your-api-key
```

The script will:
1. Submit a StartApp request with Docker Compose configuration
2. Return a task ID for tracking deployment progress
3. The application will be measured and extended to TEE runtime measurements
4. For actual deployment, please modify Docker Compose and its configuration
5. RootFS space is limited, please store data in the /data directory

#### Checking Task Status

Monitor the deployment progress:

```bash
./examples/get_task_status.sh <TASK_ID> [HOST] [PORT]
```

#### Stopping an Application

Stop and remove a deployed application:

```bash
# Basic usage
./examples/stop_app.sh <APP_ID>

# Custom host and API key
./examples/stop_app.sh <APP_ID> <HOST> <PORT> <API_KEY>

# Example
./examples/stop_app.sh my-nginx-app your-cvm-instance-host port your-api-key
```

#### Getting Application Logs

Retrieve logs from a running application:

```bash
./examples/get_app_log.sh <APP_ID> [LINES] [SERVICE_NAME] [HOST] [PORT]
```

#### Listing Deployed Applications

View all deployed applications with their measurements:

```bash
./examples/list_app_measurements.sh [HOST] [PORT] [DEPLOYER_FILTER]
```

#### Getting Attestation Evidence

Retrieve TEE attestation evidence for verification:

```bash
./examples/get_evidence.sh [HOST] [PORT] [REPORT_DATA_HEX]
```

## API Reference

0G Tapp provides a gRPC API with the following key services:

### Application Management
- `StartApp`: Deploy a new application (async)
- `StopApp`: Stop and remove an application
- `GetAppInfo`: Get application configuration
- `GetAppLogs`: Retrieve application logs
- `ListAppMeasurements`: List all deployed applications with measurements

### Task Management
- `GetTaskStatus`: Check status of async operations

### Attestation
- `GetEvidence`: Generate TEE attestation evidence

### Key Management
- `GetAppKey`: Get application-bound public key
- `GetAppSecretKey`: Retrieve application private key (local access only)

### Service Monitoring
- `GetServiceLogs`: Retrieve service logs

## Security

### Security Model: Malicious Deployer Protection

0G Tapp implements a **"Malicious Deployer" security model**, which provides the strongest security guarantees in the TEE application platform space. Under this model:

- **Even the deployer cannot compromise the application**
- **Deployers can only interact with the TDX instance through restricted gRPC interfaces** - they cannot arbitrarily access the TDX instance
- Applications run in isolated TEE environments with cryptographic integrity
- Runtime measurements ensure that deployed code matches what was intended
- Private keys are bound to specific application measurements and cannot be extracted
- TEE hardware protections prevent unauthorized access to application memory and secrets

This means that once an application is deployed and measured:
1. The deployer cannot access application secrets or private keys
2. The deployer cannot modify the running application without detection
3. All application state and data remain confidential within the TEE
4. Remote attestation allows third parties to verify application integrity

This security model is ideal for scenarios requiring maximum trust minimization, such as:
- Multi-party computation platforms
- Decentralized oracle networks
- Privacy-preserving data processing
- Trustless application execution

### API Key Authentication

Protected methods require API key authentication via the `x-api-key` header:

```bash
# Set API key in environment
export TAPP_API_KEY="your-secret-api-key"
```

Configure API keys in the service configuration file under `[server.api_key]` section.

### Trusted Execution Environment

All applications run within TEE boundaries and are cryptographically measured. The runtime measurements are extended to the TEE event log for remote attestation.

## Building from Source

```bash
# Clone repository
git clone https://github.com/0glabs/0g-tapp.git
cd 0g-tapp

# Build
cargo build --release

# Run
./target/release/tapp-service --config config.toml
```

## Configuration

Create a `config.toml` file:

```toml
[server]
host = "0.0.0.0"
port = 50051

[server.api_key]
enabled = true
keys = ["your-secret-api-key-1", "your-secret-api-key-2"]
protected_methods = ["StartApp", "StopApp"]

[boot]
socket_path = "/var/run/docker.sock"

[logging]
level = "info"
path = "/var/log/tapp/"
```

## Examples

See the `examples/` directory for complete usage examples:
- `start_app.sh` - Deploy an nginx application
- `start_0g_provider.sh` - Deploy 0G Serving Provider
- `stop_app.sh` - Stop an application
- `get_evidence.sh` - Retrieve attestation evidence
- `get_app_log.sh` - View application logs

## License

[License information]

## Contributing

[Contributing guidelines]
