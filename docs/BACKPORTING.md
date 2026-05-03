# Git Workflow: Private Repo with Public Template Backporting

This guide explains how to maintain a private repository derived from a public template while retaining the ability to easily backport fixes or features to the original template.

## Phase 1: Initialization (Create the Private Repo)

1.  **Create a new private repository** on GitHub. Do **not** initialize it with any files (README, License, etc.).
2.  **Duplicate the template** using a bare clone to preserve all history and branches:

```bash
# Clone the template as a bare repository
git clone --bare https://github.com/original-owner/public-template.git temp-clone
cd temp-clone

# Mirror-push to your new private repository
git push --mirror https://github.com/your-username/private-repo.git

# Clean up
cd ..
rm -rf temp-clone
```

## Phase 2: Local Setup

1.  **Clone your private repository**:
    ```bash
    git clone https://github.com/your-username/private-repo.git
    cd private-repo
    ```

2.  **Add the public template as a remote** named `template`:
    ```bash
    git remote add template https://github.com/original-owner/public-template.git
    git fetch template
    ```

---

## Phase 3: Daily Workflow

### 1. Staying Up-to-Date with changes in the template
To pull new improvements from the public template into your private repo:
```bash
git checkout main
git fetch template
git merge template/main
# Resolve any conflicts and push to your private origin
git push origin main
```

### 2. Backporting Changes to the Template
When you have a commit in your private repo that should be contributed back to the public template:

1.  **Create a clean branch** based on the template's current state:
    ```bash
    git fetch template
    git checkout -b fix-backport template/main
    ```

2.  **Cherry-pick the specific commit(s)** from your private history:
    ```bash
    # Replace <commit-hash> with your commit ID
    git cherry-pick <commit-hash>
    ```

3.  **Push the branch** to the public template (or your public fork) and create a Pull Request:
    ```bash
    git push template fix-backport
    ```

4.  **Cleanup**: Once the PR is merged, delete the local backport branch:
    ```bash
    git checkout main
    git branch -D fix-backport
    ```

## Summary of Remotes
- `origin`: Your private repository (Primary workspace).
- `template`: The public source repository (Upstream source and backport target).
