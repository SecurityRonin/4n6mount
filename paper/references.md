# References — Deletion SoK

**Verification scope (stated precisely; see the Citation Audit appendix for per-URL records).** URLs marked *verified* below were fetched on the access date shown in the appendix and returned HTTP 200 with the expected MIME type; HTML spec pages were additionally checked for the presence of the cited sections (exFAT §6.2.1/§6.3.4/§7.1.5; linux-ntfs file-record layout; TN1150 B-tree/extents/journal sections; Btrfs EXTENT_ITEM; F2FS on-disk layout). *This is not an "every URL verified" claim*: entries whose publisher pages were bot-blocked (403/444) or otherwise unconfirmed are individually flagged, both inline and in the appendix.

1. **Brian Carrier, *File System Forensic Analysis***, Addison-Wesley, 2005. ISBN 978-0-321-26817-4. Publisher page: <https://www.informit.com/store/file-system-forensic-analysis-9780321268174>. Canonical reference for FAT/NTFS/ExtX/UFS deletion behavior and the file-name/metadata/content category model (ch. 8–17). **Chapter-level attributions in the paper are from memory of the print edition; page-level pin-cites must be added from a physical copy before external submission, and any claim not found on inspection is to be deleted** (this applies in particular to the FAT32 high-word item, already demoted to unverified folklore in §3.1.1).

2. **Microsoft, *FAT: General Overview of On-Disk Format* (fatgen103, v1.03)**, 2000. PDF (verified; embedded document title matches — content streams are Flate-compressed so field-level text probes do not resolve, noted in the appendix): <https://www.fysnet.net/docs/fatgen103.pdf>. Sections cited: directory entry structure (`DIR_Name[0] = 0xE5` free marker, `DIR_FstClusHI`/`DIR_FstClusLO` layout), long directory entries, FAT entry values. **Correction from draft 1:** the previously cited MIT mirror (`academy.cba.mit.edu/.../FAT.pdf`) is a *different, later Microsoft-Confidential draft*, not fatgen103 — it has been removed as a source. Note the spec defines layout and the free markers; it does **not** prescribe deletion-time driver behavior.

3. **Microsoft, *exFAT file system specification***, Microsoft Learn (verified). <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>. Sections cited: §6.2.1 EntryType (01h–7Fh = unused entry), §6.2.1.4/§6.3.1.4 InUse field, §6.3.4.2/§6.4.2.2 NoFatChain, §7.1.5 Allocation Bitmap. The spec declares unused-entry fields *undefined* — field retention after deletion is driver behavior, not a spec guarantee.

4. **linux-ntfs project (Richard Russon et al.), *NTFS Documentation*** (all pages verified). File record: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/file_record.html>; `$FILE_NAME`: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/file_name.html>; `$DATA`: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/data.html>; `$LogFile`: <https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html>; `$UsnJrnl`: <https://flatcap.github.io/linux-ntfs/ntfs/files/usnjrnl.html>. Reverse-engineered community reference; no public Microsoft on-disk NTFS specification exists, so every NTFS claim is at best [C].

5. **R. Nordvik, H. Georges, F. Toolan, S. Axelsson, "Reverse engineering of ReFS"**, *Digital Investigation* 30 (2019). Publisher page (bot-blocked 403 — **not verified here**, listing confirmed via search): <https://www.sciencedirect.com/science/article/pii/S1742287619301252>. Open-access record via NTNU Open (verified): <https://ntnuopen.ntnu.no/ntnu-xmlui/handle/11250/2639687>.

6. **P. Prade, T. Groß, A. Dewald, "Forensic Analysis of the Resilient File System (ReFS) Version 3.4"**, DFRWS EU 2020. PDF (verified; content spot-checked to match the cited ReFS 3.4/COW/deleted-page material): <https://fidi.mlsec.org/docs/2020-dfrws.pdf>. Publisher page: <https://www.sciencedirect.com/science/article/pii/S266628172030010X> (bot-blocked — not verified).

7. **"Forensic Analysis of ReFS Journaling"**, DFRWS APAC 2021. PDF (verified): <https://dfrws.org/wp-content/uploads/2021/01/2021_APAC_paper-forensic_analysis_of_refs_journaling.pdf>. Presentation page: <https://dfrws.org/presentation/forensic-analysis-of-refs-journaling/>.

8. **Linux kernel documentation, *ext4 Data Structures and Algorithms*** (verified). Index: <https://docs.kernel.org/filesystems/ext4/index.html>; dynamic structures: <https://docs.kernel.org/filesystems/ext4/dynamic.html>; global structures: <https://docs.kernel.org/filesystems/ext4/globals.html>. Layout reference; deletion policy is implementation behavior sourced separately ([9], [21]).

9. **K. D. Fairbanks, "An analysis of Ext4 for digital forensics"**, *Digital Investigation* 9 (2012) S118–S130, DFRWS USA 2012. Presentation page (verified): <https://dfrws.org/presentation/an-analysis-of-ext4-for-digital-forensics/>; slides PDF (verified): <https://dfrws.org/sites/default/files/session-files/2012_USA_pres-an_analysis_of_ext4_for_digital_forensics.pdf>; publisher page: <https://www.sciencedirect.com/science/article/pii/S1742287612000357> (bot-blocked — not verified).

10. **Silicon Graphics / XFS developers, *XFS Algorithms & Data Structures* (on-disk format reference)**. PDF, kernel.org (verified): <https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf> (same document at <https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf>). Sections cited: directory formats (shortform/block/leaf/node), dir2 data-unused structure (`freetag = 0xFFFF` + length overwriting the entry head, trailing tag), AGI unlinked lists, inode core and data-fork literal area. The document specifies structures, **not** post-unlink residue — residue claims in §3.2.2 are [C] (tool evidence) or [I].

11. **Btrfs documentation, *On-disk Format*** (verified). <https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html>. Sections cited: EXTENT_ITEM back-references, reserved tree objectids, superblock generations. The page self-describes as partly outdated (copied from the original wiki); the claims cited are stable format basics.

12. **Sun Microsystems, *ZFS On-Disk Specification* (draft, 2006)**. PDF (verified; PDF magic + expected front matter): <https://www.giis.co.in/Zfs_ondiskformat.pdf>; maintained archive by Matt Ahrens (verified): <https://github.com/ahrens/zfsondisk>. Sections cited: §1.3.4 uberblock (128-slot ring), block pointers, DMU/MOS structure. The 2006 draft predates newer features; claims cited are the stable base format.

13. **N. L. Beebe, S. D. Stacy, D. Stuckey, "Digital forensic implications of ZFS"**, *Digital Investigation* 6 (2009) S99–S107, DFRWS 2009. Presentation page (verified): <https://dfrws.org/presentation/digital-forensic-implications-of-zfs/>; publisher page: <https://www.sciencedirect.com/science/article/pii/S1742287609000449> (bot-blocked — not verified).

14. **Linux kernel documentation, *Flash-Friendly File System (F2FS)*** (verified). <https://docs.kernel.org/filesystems/f2fs.html>. Sections cited: on-disk layout (SB/CP/SIT/NAT/SSA/Main), NAT design, checkpoint alternation, dentry-block layout (bitmap + dentry + filename arrays), roll-forward recovery. Layout only; unlink behavior is sourced to the implementation [41].

15. **Apple, Technical Note TN1150, *HFS Plus Volume Format*** (verified). <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>. Sections cited: Catalog File, B-Trees (packed records + reverse offset table), Extents Overflow File, HFS Plus Journal. TN1150 specifies layout; it does **not** specify the deletion algorithm, byte wiping, or node-merge policy — §3.2.1 treats those as [C]/[I] accordingly.

16. **A. Burghardt, A. J. Feldman, "Using the HFS+ journal for deleted file recovery"**, *Digital Investigation* 5 (2008), DFRWS 2008. Presentation page (verified): <https://dfrws.org/presentation/using-the-hfs-journal-for-deleted-file-recovery/>. (A direct dfrws.org PDF path returned 404 at verification; the presentation page is the stable citation.)

17. **Apple, *Apple File System Reference***. PDF (verified, ~520 KB): <https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf>. Sections cited: container superblock & checkpoints, object map (oid/xid), file-system objects (`j_inode_val`, `j_drec_val`, `j_file_extent_val`), snapshots, encryption.

18. **K. H. Hansen, F. Toolan, "Decoding the APFS file system"**, *Digital Investigation* 22 (2017) 107–132, DOI 10.1016/j.diin.2017.07.003. Publisher page: <https://www.sciencedirect.com/science/article/abs/pii/S1742287617301408> (bot-blocked — not verified); DOI listing: <https://dl.acm.org/doi/10.1016/j.diin.2017.07.003> (not independently fetched).

19. **ECMA-119, *Volume and File Structure of CDROM for Information Interchange*** (= ISO 9660) (verified). <https://ecma-international.org/publications-and-standards/standards/ecma-119/>.

20. **ECMA-167, *Volume and File Structure for Write-Once and Rewritable Media using Non-Sequential Recording*** (basis of UDF) (verified). <https://ecma-international.org/publications-and-standards/standards/ecma-167/>. **OSTA note:** on 2026-07-19 a fetch of `http://www.osta.org/specs/pdf/udf260.pdf` returned HTTP 200 with `Content-Type: text/html` instead of a PDF — a fake-200 observed once in this audit (response headers recorded in the appendix; body hash not retained, and a later independent re-fetch was blocked, so the observation is recorded as unreproduced). ECMA-167 is cited as the verified normative basis instead.

21. **extundelete** (ext3/ext4 undeletion via jbd2 journal) (verified). <https://extundelete.sourceforge.net/>. Its documentation describes ext3's block-pointer zeroing at deletion and the journal-copy recovery method. (The related `ext4magic` project site returned 403 at verification time and is cited by name only.)

22. **xfs_undelete** (XFS undeletion via residual inode extent data) (verified). <https://github.com/ianka/xfs_undelete>. Tool evidence, version-scoped to what its author tested; not a normative statement about current `xfs_ifree` behavior.

23. **Autopsy** (GUI over The Sleuth Kit) (verified). <https://www.autopsy.com/>.

24. **OpenZFS, `zpool-import(8)`** (read-only import / rewind options) (verified). <https://openzfs.github.io/openzfs-docs/man/master/8/zpool-import.8.html>.

25. **X-Ways Forensics** (verified). <https://www.x-ways.net/forensics/>.

26. **FTK Imager** (Exterro) (verified). <https://www.exterro.com/digital-forensics-software/ftk-imager>. (EnCase Forensic is cited by name; OpenText's product page returned HTTP 444 to automated fetch and is not hotlinked.)

27. **NILFS2** (verified). Kernel documentation: <https://docs.kernel.org/filesystems/nilfs2.html>; project site (continuous checkpointing, `lscp`, snapshots, GC/protection period): <https://nilfs.sourceforge.io/>.

28. **G. Bell, R. Boddington, "Solid State Drives: The Beginning of the End for Current Practice in Digital Forensic Recovery?"**, *Journal of Digital Forensics, Security and Law* 5(3), 2010 (verified). <https://commons.erau.edu/jdfsl/vol5/iss3/1/>.

29. **`xattr(7)` — extended attributes**, Linux man-pages (verified). <https://man7.org/linux/man-pages/man7/xattr.7.html>.

30. **4n6mount** (this paper's motivating application). Repository: `~/src/4n6mount` (README; `docs/decisions/0008-deleted-in-place-orphans.md`, status *Proposed — not implemented* as of 2026-07-19). Public repo link to be added at publication.

31. **C. Lee, D. Sim, J.-Y. Hwang, S. Cho, "F2FS: A New File System for Flash Storage"**, USENIX FAST '15 (verified). Paper page: <https://www.usenix.org/conference/fast15/technical-sessions/presentation/lee>; PDF: <https://www.usenix.org/system/files/conference/fast15/fast15-paper-lee.pdf>.

32. **The Sleuth Kit man pages** (verified): `fls` <https://sleuthkit.org/sleuthkit/man/fls.html>; `icat` <https://sleuthkit.org/sleuthkit/man/icat.html>; `tsk_recover` <https://sleuthkit.org/sleuthkit/man/tsk_recover.html>. (The sleuthkit wiki page for fls returned 404; the man pages are the stable citations.)

33. **fatcat** (FAT explore/undelete) (verified). <https://github.com/Gregwar/fatcat>.

34. **PhotoRec** (CGSecurity) (verified). <https://www.cgsecurity.org/wiki/PhotoRec>.

35. **foremost** (verified). <https://foremost.sourceforge.net/>.

36. **libewf** (includes `ewfmount`) (verified). <https://github.com/libyal/libewf>.

37. **libguestfs** (verified). <https://libguestfs.org/>.

38. **imagemounter** (verified). <https://github.com/ralphje/imagemounter>.

39. **Arsenal Image Mounter** (verified). <https://arsenalrecon.com/products/arsenal-image-mounter>.

40. **M. K. McKusick, G. R. Ganger, "Soft Updates: A Technique for Eliminating Most Synchronous Writes in the Fast Filesystem"**, USENIX ATC 1999 (FREENIX track). PDF (verified): <https://web.stanford.edu/class/archive/cs/cs240/cs240.1066/readings/mckusick99.pdf>. Cited for the FFS deallocation discipline (link-count and block-pointer handling as ordered-update policy); **not** cited as evidence for any per-OS/per-version residue matrix.

41. **Linux kernel, `fs/f2fs/dir.c`** (`f2fs_delete_entry`) (tree page verified). <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/f2fs/dir.c>. Implementation source for the F2FS unlink path: clears dentry-bitmap bits without zeroing the dentry/name arrays. Version-scoped to the mainline tree at the access date; pin to a tagged release (`?h=vX.Y`) when the §7 protocol runs.

## Cited-by-name, not hotlinked (no stable verified URL at draft time)

- **D. Farmer, W. Venema, *Forensic Discovery***, Addison-Wesley, 2005 (free-space persistence measurement).
- **R. Shullich, "Reverse Engineering the Microsoft exFAT File System"**, SANS Reading Room, 2009 (pre-dated Microsoft's public spec; superseded as a primary source by [3]).
- **S. Garfinkel**, fragment-aware file carving and the associated public research corpora (carving literature anchor, §8).
- **ntfsundelete** (ntfs-3g suite), **TestDisk**, **scalpel**, **xmount**, **affuse**, **ext4magic** — named as class members in §4; their pages were either not checked or returned errors at verification time (see appendix).

## Appendix: Citation Audit

Access date for all rows: **2026-07-19** (automated fetch, desktop-browser User-Agent; method: HEAD, falling back to GET on 403/404/405). MIME is the returned `Content-Type`. Content checks beyond MIME are noted. Byte sizes recorded where the server returned `Content-Length`. Response bodies were not archived; for external submission, re-run the audit with body hashes retained (the §7 pre-registration should include that).

| Ref | URL (abbreviated) | HTTP | MIME | Note |
|---|---|---|---|---|
| 1 | informit.com/store/file-system-forensic-analysis… | 200 | text/html | catalog page |
| 2 | fysnet.net/docs/fatgen103.pdf | 200 | application/pdf | 168,521 B; embedded title "FAT: General Overview of On-Disk Format" confirmed; content streams compressed, field-level probes N/A |
| 2 (removed) | academy.cba.mit.edu/…/FAT.pdf | 200 | application/pdf | **wrong document** (later Microsoft-Confidential draft) — removed as a source |
| 3 | learn.microsoft.com/…/exfat-specification | 200 | text/html | cited sections §6.2.1/§6.3.4/§7.1.5 confirmed present |
| 4 | flatcap.github.io/linux-ntfs/… (5 pages) | 200 | text/html | file-record layout + attribute pages confirmed |
| 5 | sciencedirect.com/…/S1742287619301252 | 403 | text/html | **bot-blocked, unverified**; NTNU Open record 200 |
| 6 | fidi.mlsec.org/docs/2020-dfrws.pdf | 200 | application/pdf | content spot-checked (ReFS 3.4) |
| 6 | sciencedirect.com/…/S266628172030010X | — | — | **not fetched** |
| 7 | dfrws.org/…/2021_APAC_paper-forensic_analysis_of_refs_journaling.pdf | 200 | application/pdf | |
| 8 | docs.kernel.org/filesystems/ext4/… (3 pages) | 200 | text/html | |
| 9 | dfrws.org presentation + slides PDF | 200 | text/html; application/pdf | ScienceDirect page **not verified** (bot-blocked class) |
| 10 | mirrors.edge.kernel.org/…/xfs_filesystem_structure.pdf | 200 | application/pdf | 2,495,550 B |
| 11 | btrfs.readthedocs.io/…/On-disk-format.html | 200 | text/html | EXTENT_ITEM section confirmed |
| 12 | giis.co.in/Zfs_ondiskformat.pdf | 200 | application/pdf | 507,346 B; PDF magic confirmed |
| 12 | github.com/ahrens/zfsondisk | 200 | text/html | |
| 13 | dfrws.org/presentation/digital-forensic-implications-of-zfs/ | 200 | text/html | ScienceDirect page **not verified** |
| 14 | docs.kernel.org/filesystems/f2fs.html | 200 | text/html | layout sections confirmed |
| 15 | developer.apple.com/…/tn1150.html | 200 | text/html | B-tree/extents/journal sections confirmed |
| 16 | dfrws.org/presentation/using-the-hfs-journal-for-deleted-file-recovery/ | 200 | text/html | direct PDF path 404 |
| 17 | developer.apple.com/…/Apple-File-System-Reference.pdf | 200 | application/pdf | 532,193 B |
| 18 | sciencedirect.com/…/S1742287617301408 | — | — | **not fetched (bot-blocked class); unverified** |
| 19, 20 | ecma-international.org (ECMA-119, ECMA-167) | 200 | text/html | |
| 20 (note) | osta.org/specs/pdf/udf260.pdf | 200 | text/html | **fake-200 observed once** (HTML where PDF expected); body hash not retained; independent re-check blocked — recorded as unreproduced |
| 21 | extundelete.sourceforge.net | 200 | text/html | ext4magic.sourceforge.net returned **403** |
| 22 | github.com/ianka/xfs_undelete | 200 | text/html | |
| 23–29, 31–39 | tool/manual/paper pages as listed above | 200 | text/html or application/pdf | exceptions: linux.die.net/man/8/ntfsundelete **403**; opentext.com product page **444**; wiki.sleuthkit.org Fls **404** |
| 40 | web.stanford.edu/…/mckusick99.pdf | 200 | application/pdf | 126,203 B |
| 41 | git.kernel.org/…/fs/f2fs/dir.c | 200 | text/html | mainline tree view |
