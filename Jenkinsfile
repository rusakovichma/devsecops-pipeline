// This pipeline revolves around building a Docker image:
// - Lint: Lints a Dockerfile using hadolint
// - detect new secrets: Detect new secrets
// - sonar scanner: Scan source code for vulnerabilities
// - dependency check: Test for insecure third party libraries
// - anchore-engine: docker images scanning
// - nikto, OWASP ZAP - dynamic application security scanning

pipeline {
    environment { // Environment variables defined for all steps
        TOOLS_IMAGE = "127.0.0.1:5000/tools-image"
        DOCKER_IMAGE = "127.0.0.1:5000/juice-shop"
        DOCKER_IMAGE_LAB_NET = "registry.demo.local:5000/juice-shop"
	SONAR_KEY = "juice-shop"
    }

    agent any

    stages {
        stage("lint") {
            agent {
                docker {
                    image "docker.io/hadolint/hadolint:v1.18.0"
                    reuseNode true
                }
            }
            steps {
                sh label: "Lint Dockerfile", script: "hadolint Dockerfile > hadolint-results.txt"
            }
        }

        stage("detect new secrets") {
            agent {
                docker {
                    image "${TOOLS_IMAGE}"
                    args "--volume /etc/passwd:/etc/passwd:ro"
                    reuseNode true
                }
            }
            steps {
                script {
                    def result = sh label: "detect-secrets",
                        script: """\
                            detect-secrets-hook --no-verify \
                                                -v \
                                                --baseline .secrets.baseline.json \
                            \$(git diff-tree --no-commit-id --name-only -r ${GIT_COMMIT} | xargs -n1)
                        """,
                        returnStatus: true
                        
                        if (result == 1) {
                            error("unaudited secrets have been found")
                        }
                }
            }
        }

       stage("sonnarscanner") {
           agent {
               docker {
                   image "${TOOLS_IMAGE}"
                   // Make sure that username can be mapped correctly
                   args "--volume /etc/passwd:/etc/passwd:ro --network lab"
                   reuseNode true
               }
           }
           steps {
               withSonarQubeEnv("sonarqube.demo.local") {
                 withEnv(['npm_config_cache=npm-cache', 'HOME=.']){
                   sh label: "clear npm cache",
                      script: "npm  cache clear --force"
                   sh label: "install prerequisites",
                      script: "npm install -D typescript"
                   sh label: "sonar-scanner",
                      script: """\
                          sonar-scanner \
                          '-Dsonar.buildString=${BRANCH_NAME}-${BUILD_ID}' \
                          '-Dsonar.projectKey=${SONAR_KEY}' \
                          '-Dsonar.projectVersion=${BUILD_ID}' \
                          '-Dsonar.sources=${WORKSPACE}'
                      """  
                 }
               }
           }
       }
       
     stage("quality gate") {
       when {
         anyOf {
           changeRequest()
           branch 'master'
         }
       }
       steps {
         timeout(time: 1, unit: 'HOURS') {
           waitForQualityGate abortPipeline: true
         }
       }
     }
  
// - Deprecated variant  
/*
    stage("quality gate") {
      steps {
        script {
          withSonarQubeEnv("sonarqube.demo.local") {
              def scannerWorkReportTask = getWorkspaceFileProperties("${env.WORKSPACE}/.scannerwork/report-task.txt")
              def sonarServerUrl = scannerWorkReportTask.getProperty('serverUrl')              
            
              def ceTask
              timeout(time: 2, unit: 'MINUTES') {
                 waitUntil {
                    withCredentials([string(credentialsId: 'SONAR_AUTH_TOKEN', variable: 'AUTH_TOKEN')]) {
                       ceTask = parseResponseFromUrl(sonarServerUrl + "/api/ce/task?id=" + scannerWorkReportTask.getProperty('ceTaskId'), "${AUTH_TOKEN}")
                    }
                 return "SUCCESS".equals(ceTask["task"]["status"])
                 }
              } 

             def qualityGateAnalysisUrl = sonarServerUrl + "/api/qualitygates/project_status?analysisId=" + ceTask["task"]["analysisId"]
             def qualityGateResp

             withCredentials([string(credentialsId: 'SONAR_AUTH_TOKEN', variable: 'AUTH_TOKEN')]) {
                 qualityGateResp = parseResponseFromUrl(qualityGateAnalysisUrl, "${AUTH_TOKEN}")
             }

             if ("ERROR".equals(qualityGateResp["projectStatus"]["status"])) {
                error "Quality Gate failure"
             }
           
         }
       } 
     }
    }
*/
    stage("dependency check") {
        agent {
            docker {
                image "owasp/dependency-check:6.4.1"
                args '''\
                    --user 0 \
                    --volume dependency-check:/usr/share/dependency-check/data:rw \
                    --volume ${WORKSPACE}:/src:ro \
                    --volume ${WORKSPACE}/reports:/reports:rw \
                    --entrypoint ""
                '''
                reuseNode true 
            }
        }
        steps {
             script {
                 def result = sh label: "dependency-check", returnStatus: true,
                     script: """\
                        mkdir -p reports &>/dev/null
                        /usr/share/dependency-check/bin/dependency-check.sh \
                        --failOnCVSS 10 \
                        --out "${WORKSPACE}/reports" \
                        --project "${JOB_BASE_NAME}" \
                        --scan "/src"
                     """
                 if (result > 0) {
                      unstable(message: "Insecure libraries found")
                 } 
             }
        }
    }
   
    stage("Build image") {
        steps {
            script {
                // Use commit tag if it has been tagged
                tag = sh(returnStdout: true, script: "git tag --contains").trim()
                if ("$tag" == "") {
                    if ("${BRANCH_NAME}" == "master") {
                        tag = "latest"
                    } else {
                        tag = "${BRANCH_NAME}"
                    }
                }
                image = docker.build("$DOCKER_IMAGE:$tag")
            }
        }
    }

    stage("Push to registry"){
        steps {
	    script {
                sh label: "Push to registry", script: "docker push ${DOCKER_IMAGE}:$tag"
            }
        }
    }

    stage("Scan container") {
        agent {
            docker {
                image "$TOOLS_IMAGE"
                //Make sure that container can access anchore-engine_api_1
                args "--network=lab --volume ${WORKSPACE}/anchore-policy:/anchore-policy:ro"
                reuseNode true
            }
        }
        steps {
            // Continue the build, even after policy failure
            script {
                 sh label: "Ensure anchore is available",
                     script: "anchore-cli system status"
                 sh label: "Add policy to Anchore engine",
                     script: "anchore-cli policy add /anchore-policy/policybundle.json"
                 def policyId = sh (
                     script: "anchore-cli policy list | awk 'NR==2{print \$1}'",
                     returnStdout: true
                 ).trim()
                 sh label: "Activate the policy",
                     script: "anchore-cli policy activate ${policyId}"
                 sh label: "Add to queue",
                     script: "anchore-cli image add ${DOCKER_IMAGE_LAB_NET}:$tag"
                 sh label: "Wait for analysis",
                     script: "anchore-cli image wait ${DOCKER_IMAGE_LAB_NET}:$tag"
                 sh label: "Generate list of vulnerabilities",
                     script: "anchore-cli image vuln $DOCKER_IMAGE_LAB_NET:$tag all | tee anchore-results.txt"
                 def result = sh label: "Check policy",
                     script: "anchore-cli evaluate check ${DOCKER_IMAGE_LAB_NET}:$tag --detail >> anchore-results.txt"

                 if (result > 0) {
                      unstable(message: "Policy check failed")
                 }
            }
        }
    }

    stage("Launch sidecar") {
        steps {
            sh label: "Start sidecar container",
                script: """\
                    docker run --detach \
                               --network lab \
                               --name ${JOB_BASE_NAME}-${BUILD_ID}  \
                               --rm \
                               ${DOCKER_IMAGE_LAB_NET}:${tag}
               """
        }
    }

    stage("nikto") {
        agent {
            docker {
                image "$TOOLS_IMAGE"
                args "--network=lab"
                reuseNode true 
            }
        }
        steps {
            script {
                def result = sh label: "nikto", returnStatus: true,
                    script: """\
                        mkdir -p reports &>/dev/null
                        curl --max-time 120 \
                            --retry 60 \
                            --retry-connrefused \
                            --retry-delay 5 \
                            --fail \
                            --silent http://${JOB_BASE_NAME}-${BUILD_ID}:3000 || exit 1
                        nikto.pl -ask no \
                            -nointeractive
                            -Plugins '@@ALL;-sitefiles' \
                            -output reports/nikto.html \
                            -host http://${JOB_BASE_NAME}-${BUILD_ID}:3000 > nikto.pl-results.txt
                    """

               if (result > 0) {
                   unstable(message: "Web server scanner issues found")
               }
            }
        }
    }
    
    stage("OWASP ZAP") {
        agent {
            docker {
                image "owasp/zap2docker-weekly"
                //Make sure that the container can access the sidecar
                args "--network=lab --tty --volume ${WORKSPACE}:/zap/wrk"
                reuseNode true
            }
        }
        steps {
            script {
                def result = sh label: "OWASP ZAP", returnStatus: true,
                    script: """\
                        mkdir -p reports &>/dev/null
                        curl --max-time 120 \
                            --retry 60 \
                            --retry-connrefused \
                            --retry-delay 5 \
                            --fail \
                            --silent http://${JOB_BASE_NAME}-${BUILD_ID}:3000 || exit 1
                        zap-baseline.py \
                        -t "http://${JOB_BASE_NAME}-${BUILD_ID}:3000" \
                        -m 5 \
                        -T 5\
                        -I \
                        -r reports/zapreport.html
                """
                if (result > 0) {
                    unstable(message: "OWASP ZAP issues found")
                }   
            }
        }
    }
   }
   post {
        always {
             sh label: "Stop sidecar container", script: "docker stop ${JOB_BASE_NAME}-${BUILD_ID}"

             archiveArtifacts artifacts: "*-results.txt"

             publishHTML([
                 allowMissing: true,
                 alwaysLinkToLastBuild: true,
                 keepAll: false,
                 reportDir: "reports",
                 reportFiles: "dependency-check-report.html",
                 reportName: "Dependency Check Report"
             ])

             publishHTML([
                 allowMissing: true,
                 alwaysLinkToLastBuild: true,
                 keepAll: true,
                 reportDir: "reports",
                 reportFiles: "nikto.html",
                 reportName: "Nikto.pl scanreport"
            ])

            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: "reports",
                reportFiles: "zapreport.html",
                reportName: "OWASP ZAP scanreport"
            ])
        }
   }
}

def Properties getWorkspaceFileProperties(filename) {
    def properties = new Properties()
    properties.load(new StringReader(readFile(filename)))
    return properties
}

@NonCPS
def parseResponseFromUrl(String url, String authToken) {
    def response  = sh(script: "curl -u ${authToken}: ${url}", returnStdout: true) 
    def parsedResponse = new groovy.json.JsonSlurperClassic().parseText(response)
    return parsedResponse
}
