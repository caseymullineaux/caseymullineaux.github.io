---
layout: post
title: 'Infrastructure as code with Azure DevOps - Part 1: Getting started'
date: 2019-01-11
author: Casey Mullineaux
cover: '/images/posts/azure-devops/part1-image2.png'
tags: arm azure devops
---
It seems like on every blog or forum I read someone is talking about how the discipline of DevOps can "increase agility" and deliver value with an "increased velocity". 

What I **don't** see a lot of, is someone explaining how to configure and use the tooling that makes that possible - especially in the context of deploying infrastructure to Azure via ARM. Hopefully I can help fill that gap.

In this blog series i'll explain how go from zero to hero, deploying infrastructure-as-code into Azure through a simple CI/CD pipeline using Azure DevOps. 

# What is Azure DevOps?

Azure DevOps (formerly known as Visual Studio Team Services (VSTS)) is a free* and extensible software platform that provides all the features a developer needs to develop, test, and release software.

Azure DevOps is split up into 5 main areas:
1. Azure Boards (work tracking)
2. Azure Pipelines (CI/CD)
3. Azure Repos (source control)
4. Azure Test Plans (application test management)
5. Azure Artifacts (package management)

To keep things simple, i'm going to be focusing on the meat and potatoes of what Azure DevOps offers, which is Azure Repos and Azure Pipelines. 

These two features allows us to store and manage ARM templates in source control, and deploy them into Azure automatically using a CI/CD pipeline.

# Getting started

Getting started is super easy and can be done in less than five minutes.

## Create an Azure DevOps account

Head to [dev.azure.com](https://dev.azure.com) and click **Start free** to create a new account.

![image1](/images/posts/azure-devops/part1-image1.png)

Once you sign in with your Microsoft account, clicking continue will provision a new Azure DevOps instance your Azure tenancy. 

![image2](/images/posts/azure-devops/part1-image2.png)

<p class="alert alert-info">
    <i class="fa fa-info-circle"></i> <strong>Info</strong><br>
        If you login to the Azure portal, you can see the resource that was provisioned by browsing to All services --> Azure DevOps organizations <br>
    <img src="/images/posts/azure-devops/part1-image3.png">
</p>

## Create a new project

When the Azure DevOps instance has been created, you'll immediately be prompted to create a new project. 

Think of a "project" as a bucket that will contain all of your source code and build pipelines related to a particular application or system. In the event that you want to manage which users can access the source code and CI/CD pipelines, projects can also be used as a permission boundary.

<p class="alert alert-success">
    <i class="fa fa-check-circle"></i> <strong>Tip</strong><br>
     It is a good rule of thumb to create a new project for each application or system you want to manage via CI/CD.
</p>

Give the project a name and choose whether you want the project to be public or private. In most cases, you'd want to keep your junk private.

![image4](/images/posts/azure-devops/part1-image4.png)
> A subtle call out to [The Phoenix Project](https://www.amazon.com/Phoenix-Project-DevOps-Helping-Business/dp/1942788290?SubscriptionId=AKIAILSHYYTFIVPWUY6Q&tag=duckduckgo-d-20&linkCode=xm2&camp=2025&creative=165953&creativeASIN=1942788290) - recommend you pick up a copy!

That it! Told you it was simple! 

---

Continue to [Part 2 - Source Control]({% post_url /azure-devops/2019-03-01-azure-devops-part-2 %})

- Part 1 - Getting started with Azure DevOps
- [Part 2 - Source Control]({% post_url /azure-devops/2019-03-01-azure-devops-part-2 %})
- Part 3 - Builds (coming soon)
- Part 4 - Releases (coming soon)
- Part 5 - Testing infrastucture with Pester (coming soon)

