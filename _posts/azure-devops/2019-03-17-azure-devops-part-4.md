---
layout: post
title: 'Infrastructure as code with Azure DevOps - Part 4: Deploying infrastructure'
date: 2019-03-17
author: Casey Mullineaux
cover: '/images/posts/azure-devops/part4/part4-image3.png'
tags: arm azure devops
---
Finally, it's time to create some infrastructure!

A **release pipeline** defines the end-to-end process for an application to be deployed across various **stages** of testing and deployment. Much like the build phase, the release phase can also be used for testing. During the build phase we test *code* quality, however, in the release phase we test *system* quality.

Automating the deployment of code and testing of system quality is known as **Continuous Deployment** or "CD".
 
# What are we going to do?

In this post, I will show you how to:
1. Create a release pipeline
2. Create a release stage
3. Link a build artifact to a release
4. Configure release agents, jobs and tasks to deploy an ARM template
5. Configure a CD trigger to execute a release when a release completes

# Create a release pipeline

1. Click **Pipelines --> Releases --> New pipeline**
2. On the `Select a template` page, select **Empty Job**
3. A new *stage* is created automatically.
4. Give the stage a name (such as `Development`) 
5. Give the release a name (such as `Infrastructure Deployment`)
6. Click **Save**
7. **Enter a comment** and click **Save**

<video width="800" height="600" controls> 
<source src="/images/posts/azure-devops/part4/Part4-video1.mkv">
Your browser does not support the video tag.
</video>

## Stages

Pipeline stages are the control points in the release pipeline, and within a stage we can create tasks that are triggered. The critical thing to note about pipeline stages are:
- A stage cannot start unless all of its prerequisites have been fulfilled
- A stage cannot complete unless all of the tasks within it are complete
- Failures of any task usually result in the whole stage failing, and in turn, this usually fails the entire release.

In simple pipelines like the one we have created, stages can also be used to represent environments.

For example, your release pipeline might look like this:

Build --> [Dev] **!**--> [Test] **!**--> [Prod] 

1. A code change in the repo triggers an automatic build and release to the `Dev` environment.
2. ARM templates are constantly iterated upon and pushed to the repo until the requirements have been met.
3. A manual trigger progresses the next stage of the release pipeline and deploys the ARM template to the `Test` environment.
4. The end user deploys their application to the new infrastructure in the test environment and checks to make sure their application is running as expected. (This could also be done through a different team's CI/CD pipeline!)
5. One satisfied with testing, another manual trigger progress the ARM template to the `Production` environment.

# Linking a build artifact

Before we can access the ARM template in our release tasks, we need to link the artifact from a build.

1. Click **Add an artifact**
2. Click **Build** as the source type
3. **Select the project** containing the build
4. **Select the build pipeline** containing the artifact as the source
5. Set the **default version** to **latest**
6. Click **Add**

<video width="800" height="600" controls> 
<source src="/images/posts/azure-devops/part4/part4-video2.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>

# Create a release task

1. Click **Tasks --> Development**
2. Add a new **Azure Resource Group Deployment** task
3. Select the **Azure subscription** you would like to link to the deployment
4. Click **Authorize**.  A  *service connection* is created, which in turn creates a *service principal* in the subscription with `contributor` permissions that is used for deploying resources
5. Select **Create or update resource group** as the action
6. Enter the name of a new resource group to create, or select one from the list
7. Select the **Location** for the resource group
8. Select **Linked Artifact** as the **Template location**
9.  Select the ARM template from the linked artifact
10. Select a **Deployment mode**
11. Click **Save**
12. **Enter a comment** and click **Save**

<video width="800" height="600" controls> 
<source src="/images/posts/azure-devops/part4/part4-video3.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>

# Create a new release

Time to test the deployment!

1. Click **Pipelines --> Releases**
2. Select the release and click  **Create a release**
3. **Enter a release description** and click **Create**

Clicking on the **name of the release** shows a summary of the overall progress of the release.  
Clicking on the **stage** shows a summary of each step of the release.  
Clicking on the **deployment status**  shows the release logs

<video width="800" height="600" controls> 
<source src="/images/posts/azure-devops/part4/part4-video4.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>

## Release logs

The release logs show all the commands that are executed on the release agent in near real time.

Just like we did with the build logs, let's remove a layer of abstraction and look at what's happening under the hood.

### Initialize agent

This step primes the agent to be ready for the work it will need to do.

### Initialize Job

This step downloads all the task information needed for the jobs we configured and is passed onto the agent to execute.

### Download artifact

Downloads and extracts the linked artifact to the agent's local system

### Azure Deployment: Create Or Update Resource Group

This is the work that is performed by the release agent to complete the task we created.
Here we can see the agent executing a new *Azure Resource Group Deployment* using the settings we configured in the task, such as resource group name, location and ARM template.

The agent is using the ARM REST API behind the scenes to deploy the template.
This outcome is the same if you were to create a manual deployment using AzCli or Powershell

**AzCli**:
```bash
az group create --name 'ProjectPhoenix-prd' --location 'Australia East'
az group deployment create --Name 'azuredeploy-20190316-053623-9778' --resource-group 'ProjectPhoenix-prd' --template-file 'azuredeploy.json'
```

**Powershell**
```powershell
New-AzResourceGroup -Name 'ProjectPhoenix-prd' -Location 'Australia East'
New-AzResourceGroupDeployment -Name 'azuredeploy-20190316-053623-9778' -ResourceGroup 'ProjectPhoenix-prd' -TemplateFile 'azuredeploy.json'
```

### Finalize Job

Another cleanup task relating to the processes running on the agent.

# Create a CD trigger

Just like the CI trigger on our build, we can enable a CD trigger to start a release automatically.

1. Click Pipelines --> Releases
2. Select the release and click **Edit**
3. Click the **Trigger icon** on the artifact
4. **Enable** the continuous deployment trigger
5. Click **Save**
6. **Enter a comment** and click **Save**

<video width="800" height="600" controls> 
<source src="/images/posts/azure-devops/part4/part4-video5.mp4" type="video/mp4">
Your browser does not support the video tag.
</video>


# Test the automated release

Now that the CD trigger is enabled, by updating our code we trigger a new build, that when completed, triggers a new release. 

1. In VSCode, update the comment in the ARM template to indicate the test of the CD trigger

```json
{
    "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "comments": "Testing CD trigger on release pipeline",
            "type": "Microsoft.Storage/storageAccounts",
            "name": "phoenixprojectdev",
            "location": "[resourceGroup().location]",
            "apiVersion": "2018-07-01",
            "sku": {
                "name": "Standard_LRS"
            },
            "kind": "StorageV2",
            "properties": {}
        }
    ],
    "outputs": {}
}
```
2. Commit the changes with the commit message 'testing CD trigger'
3. Push the change to the master branch
4. Back in Azure DevOps, navigate to **Pipelines --> Builds**
5. Notice a new build has started with the title of the commit message
![image1](/images/posts/azure-devops/part4/part4-image1.png)
6. When the build completes, navigate to **Pipelines --> Releases**
7. Notice a new release has started. 
![image2](/images/posts/azure-devops/part4/part4-image2.png)
6. Click the name of the release (Release-2)
7. Click the **Deployment stage** and click the **Commits tab** 
8. Notice the commit message of the commit that triggered the release
![image3](/images/posts/azure-devops/part4/part4-image3.png)
9. In the Azure Portal, confirm the storage account has been deployed
![image4](/images/posts/azure-devops/part4/part4-image4.png)

---

Let's take a second to look back on what we've accomplished so far.

We have our ARM templates version controlled in source control, that when changed, triggers an automatic build. When the build completes, a new release is triggered, and the resources defined in the ARM template automatically deploy into an Azure subscription.

From code change to resource deployment with zero clicks. Now we're truly living the **infrastructure-as-code** dream.

Continue to Part 5 - Parameters files and pipeline variables (coming soon) where I'll demonstrate how to customize releases for each stage

---

- [Part 1 - Getting Started with Azure DevOps]({% post_url /azure-devops/2019-01-11-azure-devops-part-1 %})
- [Part 2 - Source Control]({% post_url /azure-devops/2019-03-01-azure-devops-part-2 %})
- [Part 3 - Creating a pipeline]({% post_url /azure-devops/2019-03-02-azure-devops-part-3 %})
- Part 4 - Deploying infrastructure
- Part 5 - Parameter files and pipeline variables (coming soon)
- Part 5 - Testing the build with Pester (coming soon)
- Part 6 - Testing the release with Pester (coming soon)
