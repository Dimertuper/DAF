#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: stats.py
Description: Collecting and logging of annotation statistics.
"""

import logging
from typing import Optional, Tuple

import pandas as pd

from ip import IP

logger = logging.getLogger("Stats")


class AnnotationStatistics:
    """Collect and log a summary of the annotation process.

    Attributes
    ----------
    config : dict
        Complete DAF configuration, used to list the enabled modules.
    """

    def __init__(self, config: dict) -> None:
        """Initialize the statistics.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.
        """

        self.config = config

    def annotator_names(self) -> dict:
        """Return a zero hit count for every enabled annotation name.

        Returns
        -------
        dict
            Annotation names mapped to 0.
        """

        annotators_dict = {}
        for key, value in self.config.items():
            if key == "daf":
                continue
            if value["enabled"] is True:
                if key == "sni_annotator":
                    for x in value["fields"]:
                        if isinstance(x, list):
                            annotators_dict[f"sni_annotator_{x[0].split(' ')[-1]}"] = 0
                        else:
                            annotators_dict[f"sni_annotator_{x.split(' ')[-1]}"] = 0
                else:
                    annotators_dict[key] = 0
        return annotators_dict

    @staticmethod
    def count_annotator_hits(ip: IP, count: dict) -> dict:
        """Count the non-empty annotations of every annotator.

        Parameters
        ----------
        ip : IP
            Annotated IP object.
        count : dict
            Annotation counts, updated in place.

        Returns
        -------
        dict
            Updated counts.
        """

        for key, value in ip.annotations.items():
            if value.is_empty():
                continue
            count[key] = count.get(key, 0) + 1
        return count

    def log(
        self,
        ip_addresses: list,
        df: pd.DataFrame = None,
        flow_stats: Optional[Tuple[int, int]] = None,
    ) -> None:
        """Log a summary of the annotation process.

        Parameters
        ----------
        ip_addresses : list
            Annotated IP objects.
        df : pd.DataFrame, optional
            Annotated flows, used to count annotated flows.
        flow_stats : tuple, optional
            ``(flow_count, annotated_flow_count)`` used when the annotated flows are not
            kept in memory, e.g. in windowed processing.
        """

        total_one_miss = 0
        total_hand_miss = 0
        no_annotation = 0
        failed_annotation = 0
        success_annotation = 0
        multi_device = 0
        annotators_dict = self.annotator_names()

        one_miss_list = []
        hand_miss_list = []
        multi_device_list = []

        for ip in ip_addresses:
            if len(ip.one_miss) > 0:
                total_one_miss += 1
                one_miss_list.append([str(ip.ip_addr), ip.one_miss])
            if len(ip.hand_miss) > 0:
                total_hand_miss += 1
                hand_miss_list.append([str(ip.ip_addr), ip.hand_miss])
            if not ip.final_annotation.is_empty():
                success_annotation += 1
            elif len(ip.annotations) == 0:
                no_annotation += 1
            else:
                failed_annotation += 1

            if len(ip.multi_device) > 0:
                multi_device += 1
                multi_device_list.append([str(ip.ip_addr), ip.multi_device])

            annotators_dict = self.count_annotator_hits(ip, count=annotators_dict)

        # IP annotation summary
        logger.info("IP annotation summary:")
        logger.info(f"  -- IP count: {len(ip_addresses)}")
        logger.info(f"  -- Success annotation: {success_annotation}")
        logger.info(f"  -- Unsuccessful annotation: {failed_annotation}")
        logger.info(f"  -- Unsuccessful annotation, caused by one miss: {total_one_miss}")
        logger.info(f"  -- No annotation: {no_annotation}")
        logger.info(f"  -- Hand annotation conflicting with the rest of annotators: {total_hand_miss}")
        logger.info(f"  -- Possible NAT: {multi_device}")

        # Annotators summary
        logger.info("Annotated IPs per annotator:")
        logger.info(f"  -- IP count: {len(ip_addresses)}")
        for key, value in annotators_dict.items():
            logger.info(f"  -- {key}: {value}")

        # Dataset annotation summary
        if df is not None:
            fields = ["group", "_class", "os_family", "os_type", "os_version"]
            rows_annotated = df[fields].notna().any(axis=1).sum()
            flow_stats = (len(df.index), rows_annotated)

        if flow_stats is not None:
            flow_count, rows_annotated = flow_stats
            logger.info("Dataset annotation summary:")
            logger.info(f"  -- Flow count: {flow_count}")
            logger.info(f"  -- Successfully annotated: {rows_annotated}")
            logger.info(f"  -- Without annotation: {flow_count - rows_annotated}")

        # Miss summary
        logger.info("Annotation fails:")
        for title, items in (
            ("Hand miss", hand_miss_list),
            ("One miss", one_miss_list),
            ("NAT", multi_device_list),
        ):
            logger.info(f"  -- {title}: ")
            if not items:
                logger.info("  --  -- None")
            for x in items:
                logger.info(f"  --  -- {x}")


__all__ = ["AnnotationStatistics"]
