# QEMU, OVMF and Secure Boot

## Description and usage

Script to generate an OVMF variables ("VARS") file with default Secure
Boot keys enrolled.  (And verify that it works.)

Simplest working invocation of the script is:

    $ ./ovmf-vars-generator output-VARS.fd

But, a more tedious variant where you can invoke the script with custom
paths and URLs:

    $ ./ovmf-vars-generator \
        --ovmf-binary /usr/share/edk2/ovmf/OVMF_CODE.secboot.fd \
        --uefi-shell-iso /usr/share/edk2/ovmf/UefiShell.iso \
        --ovmf-template-vars /usr/share/edk2/ovmf/OVMF_VARS.fd \
        --fedora-version 27 \
        --kernel-path /tmp/qosb.kernel \
        --kernel-url https://download.fedoraproject.org/pub/fedora/linux/releases/27/Everything/x86_64/os/images/pxeboot/vmlinuz \
        another-output-VARS.fd


This script does the following, in that order:

(1) Launches a QEMU guest with the UefiShell.iso as a CD-ROM.

(2) Automatically enrolls the cryptographic keys in the UEFI shell.

(3) Finally, downloads a Fedora Kernel and 'initrd' file and boots into
    it, & confirms Secure Boot is really applied.


Alternatively: You can also verify that Secure Boot is enabled properly
in a full virtual machine by explicitly running `dmesg`, and grepping
for "secure" string.  On a recent Fedora QEMU+KVM virtual machine, it
looks as follows:

    (fedora-vm)$ dmesg | grep -i secure
          [    0.000000] Secure boot enabled and kernel locked down
          [    3.261277] EFI: Loaded cert 'Fedora Secure Boot CA: fde32599c2d61db1bf5807335d7b20e4cd963b42' linked to '.builtin_trusted_keys'


## What certificates and keys are enrolled?

The following certificates and keys are enrolled by the tool:

  - As *Platform Key*, and as one of the two *Key Exchange Keys* that we
    set up, the `EnrollDefaultKeys.efi` binary on both Fedora and RHEL,
    uses the same digital certificate called `Red Hat Secure Boot
    (PK/KEK key 1)/emailAddress=secalert@redhat.com`, and Red Hat's
    Product Security team has the private key for it.

  - The certificate that is enrolled as the second *Key Exchange Key* is
    called `Microsoft Corporation KEK CA 2011`. Updates to the
    authenticated dbx (basically, "blacklist") variable, periodically
    released at http://www.uefi.org/revocationlistfile , are signed such
    that the signature chain ends in this certificate. The update can be
    installed in the guest Linux OS with the `dbxtool` utility.

  - Then, the authenticated `db` variable gets the following two
    cetificates: `Microsoft Windows Production PCA 2011` (for accepting
    Windows 8, Windows Server 2012 R2, etc boot loaders), and `Microsoft
    Corporation UEFI CA 2011` (for verifying the `shim` binary, and PCI
    expansion ROMs).


## If using the script under a recent build of OVMF and QEMU
Since QEMU commit https://git.qemu.org/?p=qemu.git;a=commitdiff;h=2d6dcbf93fb01b4a7f45a93d276d4d74b16392dd, you must invoke the script using the --oem-string option, for the EnrollDefaultKeys.efi requests that a Platform Key and First Key Exchange Key is provided, prepended by the "application prefix" (4e32566d-8e9e-4f52-81d3-5bb9715f9727). You'll need a QEMU version that includes commit 950c4e6c94b1 ("opts: don't silently truncate long option values").
This would be a way to invoke the script while using the --oem-string option:

    $ ./ovmf-vars-generator --oem-string "$(< PkKek1.oemstr)" another-output-VARS.fd

PkKek1.oemstr can be generated with the following command:

    $ openssl req -x509 -newkey rsa:2048 -nodes -subj "/C=XX/ST=Test/L=EnrollTest/O=Xxx/CN=www.example.com" -outform PEM -keyout PkKek1.private.key -out PkKek1.pem
    $ sed -e 's/^-----BEGIN CERTIFICATE-----$/4e32566d-8e9e-4f52-81d3-5bb9715f9727:/' -e '/^-----END CERTIFICATE-----$/d' PkKek1.pem | tr -d '\n' > PkKek1.oemstr


Alternatively, you can use an already existing certificate, e.g ms-kek.crt which can be obtained here: https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git/tree/ms-kek.crt.

## Using the MS Certificate:
As stated in Fedora doc: "OVMF doesn't ship with any Secure Boot keys installed, therefore we have to install some to mimic what an MS certified UEFI computer would ship."
Fortunately, OVMF ships with the binaries required to set up a default set of keys through the use of the UefiShell.iso and the EnrollDefaultKeys.efi command. All of this is done in the enroll_keys function of the script.
However, by default, EnrollDefaultKeys.efi uses MS keys for the enrollment. Therefore, we need to provide it with the MS certificate:

    # We get the MS Certificate
    $ wget https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git/plain/ms-kek.crt
    # The first 87 lines are useless here, they are just generic informations regarding the certificate
    $ sed 1,87d ms-kek.crt > ms-certificate.crt
    # Then we edit the file for our convenience (adding the application prefix and removing the '\n'
    $ sed -e 's/^-----BEGIN CERTIFICATE-----$/4e32566d-8e9e-4f52-81d3-5bb9715f9727:/' -e '/^-----END CERTIFICATE-----$/d' ms-certificate.crt | tr -d '\n' > ms-certificate-modified.crt


This would then be the command to invoke the script:

    $ ./ovmf-vars-generator \
        --ovmf-binary /usr/share/edk2/ovmf/OVMF_CODE.secboot.fd \
        --uefi-shell-iso /usr/share/edk2/ovmf/UefiShell.iso \
        --ovmf-template-vars /usr/share/edk2/ovmf/OVMF_VARS.fd \
        --fedora-version 27 \
        --kernel-path /tmp/qosb.kernel \
        --kernel-url https://download.fedoraproject.org/pub/fedora/linux/releases/27/Everything/x86_64/os/images/pxeboot/vmlinuz \
        --oem-string 4e32566d-8e9e-4f52-81d3-5bb9715f9727:$(< ms-certificate-modified.crt)
        another-output-VARS.fd
