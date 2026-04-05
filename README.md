# Malicious Package Policy
Since OPA is written in Go, it's just a single executable file.

On my local ```macOS``` workstation, I will be using ```Homebrew``` to install OPA:
```
brew install opa
```

However, for ```Linux``` endpoints, we need to download the binary, ake it executable, and move it to your path:
```
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod 755 opa
sudo mv opa /usr/local/bin/
```

## Using Standalone OPA
Standalone OPA operates in **three main modes** depending on what you're trying to do.

#### 1. The Interactive Shell (REPL)
This is great for learning ```Rego``` or testing a quick snippet, ultimately fine before we automate the golden path:

```
opa run
```
Type ```help``` inside the shell to see what you can do.

#### 2. The Evaluation Mode
This is perfect for ```CI/CD``` pipelines, or any process similar to spinning-up self-service templates. <br/>
You pass it a policy file and a data file, and it spits out the result immediately.

```
opa eval -d policy.rego -i input.json "data.example.allow"
```

Since our policy likely expects package data, I created a file named ```input.json``` and put the package info inside it: <br/>
This file could be the template for our Golden Path initiative inside our self-service, Internal Development Platform.
```
cat <<EOF > input.json
{
    "packages": [
        {
            "name": "jinja2",
            "version": "2.4.1",
            "ecosystem": "PyPI"
        }
    ]
}
EOF
```

```
cat <<EOF > policy.rego
package example

default allow = false

# For now, let's just say it's allowed if the package name isn't "malicious-pkg"
allow {
    input.packages[_].name != "malicious-pkg"
}
EOF
```

#### Understanding the OPA CLI Workflow
When you run ```opa eval```, the engine performs a "three-way merge" to get your answer:

- ```-d policy.rego``` loads your logic (the rules).
- ```-i input.json``` loads the specific object you want to test (called the **Subject**).
- ```"data.example.allow"``` tells OPA exactly which rule inside the policy you want to see the result of.

#### 3. The Server Mode (run --server)
This is how you use OPA as a sidecar or a central microservice. It exposes a REST API.

```
opa run --server policy.rego
```
By default, it listens on ```http://localhost:8181```. You can then send a POST request to get a decision:

```
curl -X POST http://localhost:8181/v1/data/example/allow \
     -d '{"input": {"user": "alice"}}'
```
