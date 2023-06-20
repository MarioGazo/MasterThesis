### Master Thesis Spring 2023 at DTU 
Analyzing and Comparing Short-Lived Data Authentication Protocols

#### Author
- Mário Gažo (s212687@student.dtu.dk)

#### Supervisor
- Luisa Siniscalchi (luisi@dtu.dk)
- Nicola Dragoni (ndra@dtu.dk)

#### Structure
- `/src` - Source files
  - `/experiments` - Benchmark individual schemes
  - `/schemes` - Time-deniable signature schemes implementation
    - `/ES` - Scheme based on discrete time intervals
    - `/TDS` - Scheme based on HIBE scheme
  - `/TLP` - Time-lock puzzle implementation
- `/out` - Benchmarking figures
- `main.py` - Main script of the project, runs all the experiments
- `requirements.txt` - Python packages needed to run this project
- `Makefile` - Run commands listed below
- `Dockerfile` - Create project image

#### Usage
The project is using Python3.7, and it can be run locally or using the Dockerized environment 

Install dependencies (some have to be installed by hand)
```
make install
```

Run the experiments
```
make exp[-es|-tds]
```

Run tests
```
make test[-es|-tds|-tlp]
```

Clean directory off cache and zip all the source files
```
make submit
```
